open Lwt.Infix;

type t = {
  sid: string,
  expiry: float,
  payload: string,
};

exception MiddleWareRequired(string);
exception BadSignature(string);

module type SessionData = {
  type t;

  let serialize: t => Lwt.t(string);
  let deserialize: string => Lwt.t(t);
};

type store = {
  create: (string, t) => Lwt.t(unit),
  update: (string, t) => Lwt.t(unit),
  get: string => Lwt.t(option(t)),
  delete: string => Lwt.t(unit),
  clear_expired: unit => Lwt.t(unit),
};

module MemorySessionStore = {
  let create = (~estimated_size=1000, ()): store => {
    let table: Hashtbl.t(string, t) =
      Hashtbl.create(~random=false, estimated_size);

    let create = (sid: string, session: t) => {
      Hashtbl.add(table, sid, session);
      Lwt.return_unit;
    };

    let get = (sid: string) => {
      let session_data = Hashtbl.find_opt(table, sid);
      Lwt.return(session_data);
    };

    let delete = (sid: string) => {
      Hashtbl.remove(table, sid);
      Lwt.return_unit;
    };

    let update = (sid: string, session: t) => {
      Hashtbl.replace(table, sid, session);
      Lwt.return_unit;
    };

    let clear_expired = () => {
      let now = Unix.time();
      Hashtbl.filter_map_inplace(
        (_sid: string, session: t) => {
          switch (Float.compare(session.expiry, now)) {
          | (-1) => None
          | _ => Some(session)
          }
        },
        table,
      );
      Lwt.return_unit;
    };

    {clear_expired, create, update, delete, get};
  };
};

module Make = (Session_data: SessionData) => {
  let session_data_key: Hmap.key((string, Session_data.t)) =
    Hmap.Key.create();
  let session_config_key: Hmap.key((string, string, store)) =
    Hmap.Key.create();

  let default_sid = "morph.sid";
  let default_store = MemorySessionStore.create(~estimated_size=1000, ());

  let rng_seed = Unix.time() |> string_of_float |> Cstruct.of_string;
  let rng_gen =
    Nocrypto.Rng.(create(~seed=rng_seed, (module Generators.Fortuna)));

  let get_session_data = (req: Morph_core.Request.t): option(Session_data.t) => {
    switch (Hmap.find(session_data_key, req.context)) {
    | None => None
    | Some((_sid, session_data)) => Some(session_data)
    };
  };

  let set_session_data =
      (req: Morph_core.Request.t, sid: string, session_data: Session_data.t) => {
    Hmap.rem(session_data_key, req.context)
    |> Hmap.add(session_data_key, (sid, session_data));
  };

  let pad_secret = secret => {
    let key_length = 32;
    let len = String.length(secret);
    let padding_size = key_length - len;
    switch (padding_size) {
    | 0 => secret
    | padding when padding < 0 => String.sub(secret, 0, key_length)
    | padding => String.make(padding, '0') ++ secret
    };
  };

  let sign = (sid, secret) => {
    let padded_secret = pad_secret(secret);
    print_endline("\n");
    print_endline(secret);
    print_endline(padded_secret);
    let cipher_key =
      Nocrypto.Cipher_block.AES.ECB.of_secret(
        Cstruct.of_string(pad_secret(secret)),
      );
    Nocrypto.Cipher_block.AES.ECB.encrypt(
      ~key=cipher_key,
      Cstruct.of_string(sid),
    )
    |> Nocrypto.Base64.encode
    |> Cstruct.to_string;
  };

  let unsign = (sid, secret) => {
    let cipher_key =
      Nocrypto.Cipher_block.AES.ECB.of_secret(
        Cstruct.of_string(pad_secret(secret)),
      );
    let bin = Cstruct.of_string(sid) |> Nocrypto.Base64.decode;

    switch (bin) {
    | None => raise(BadSignature("Signed sid is not in base64 encoding."))
    | Some(bin_sid) =>
      Nocrypto.Cipher_block.AES.ECB.decrypt(~key=cipher_key, bin_sid)
      |> Cstruct.to_string
    };
  };

  let gen_sid = secret => {
    let rng = Nocrypto.Rng.Int.gen(~g=rng_gen, 1000000);
    Random.init(rng);
    let hash1 =
      Random.bits() |> string_of_int |> Digest.string |> Digest.to_hex;
    let hash2 =
      Random.bits() |> string_of_int |> Digest.string |> Digest.to_hex;
    let sid = hash1 ++ hash2;
    sign(sid, secret);
  };

  let start_session =
      (
        session_data: Session_data.t,
        req: Morph_core.Request.t,
        res: Morph_core.Response.t,
      ) =>
    switch (Hmap.find(session_config_key, req.context)) {
    | Some((name, secret, store)) =>
      let sid = gen_sid(secret);
      let unsigned_sid = unsign(sid, secret);
      let expiry = 0.0;
      let _async =
        Session_data.serialize(session_data)
        >>= (
          payload =>
            store.create(unsigned_sid, {sid: unsigned_sid, expiry, payload})
        );
      SidCookie.set(name, sid, res);
    | None =>
      raise(
        MiddleWareRequired(
          "MorphSession middleware must be enabled to start a session.",
        ),
      )
    };

  let end_session = (req: Morph_core.Request.t, res: Morph_core.Response.t) =>
    switch (Hmap.find(session_config_key, req.context)) {
    | Some((name, _secret, store)) =>
      switch (Hmap.find(session_data_key, req.context)) {
      | Some((sid, _data)) =>
        let _async = store.delete(sid);
        SidCookie.unset(name, res);
      | None => res
      }
    | None =>
      raise(
        MiddleWareRequired(
          "MorphSession middleware must be enabled to start a session.",
        ),
      )
    };

  let get_middleware =
      (~name=default_sid, ~store=default_store, ~secret)
      : Opium_core.Filter.simple(Morph_core.Request.t, Morph_core.Response.t) =>
    (service, raw_req: Morph_core.Request.t) => {
      let req = {
        ...raw_req,
        context:
          Hmap.add(
            session_config_key,
            (name, secret, store),
            raw_req.context,
          ),
      };
      switch (SidCookie.of_req(name, req)) {
      | Some(signed_sid) =>
        let sid = unsign(signed_sid, secret);
        store.clear_expired()
        >>= (() => store.get(sid))
        >>= (
          maybe_session =>
            switch (maybe_session) {
            | Some({payload, _}) =>
              Session_data.deserialize(payload)
              >>= (
                session_data => {
                  service({
                    ...req,
                    context: set_session_data(req, sid, session_data),
                  });
                }
              )
            | None => service(req)
            }
        );
      | None => service(req)
      };
    };
};