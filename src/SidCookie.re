let rec get_session_id = (session_key, cookie_str) => {
  let cookie_length = String.length(cookie_str);
  let key_length = String.length(session_key);
  let start_of_string = 0;

  switch (String.index_opt(cookie_str, session_key.[start_of_string])) {
  | None => None
  | Some(i) =>
    let highest_len = key_length + i;
    if (cookie_length < highest_len) {
      None;
    } else if (String.sub(cookie_str, i, key_length) == session_key) {
      let partial_cookie =
        String.sub(cookie_str, highest_len, cookie_length - highest_len);

      switch (String.index_opt(partial_cookie, ';')) {
      | None => Some(partial_cookie)
      | Some(end_of_cookie) =>
        Some(String.sub(partial_cookie, start_of_string, end_of_cookie))
      };
    } else {
      get_session_id(
        session_key,
        String.sub(cookie_str, i + 1, cookie_length - (i + 1)),
      );
    };
  };
};

let of_req = (session_key, req: Morph_core.Request.t) => {
  switch (
    List.find_opt(
      ((key, _)) => String.lowercase_ascii(key) == "cookie",
      req.headers,
    )
  ) {
  | None => None
  | Some((_, cookie_str)) => get_session_id(session_key, cookie_str)
  };
};

let set = (name, sid, res: Morph_core.Response.t) => {
  let set_cookie_key = "Set-Cookie";
  let thirty_days = string_of_int(30 * 24 * 60 * 60);

  Morph_core.Response.add_header(
    (
      set_cookie_key,
      name ++ "=" ++ sid ++ "; Max-Age=" ++ thirty_days ++ ";",
    ),
    res,
  );
};

let unset = (name, res: Morph_core.Response.t) => {
  let set_cookie_key = "Set-Cookie";

  Morph_core.Response.add_header(
    (
      set_cookie_key,
      name ++ "=deleted; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
    ),
    res,
  );
};