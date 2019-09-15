module SessionData = {
  type t = {id: string};

  let serialize = data => Lwt.return(data.id);
  let deserialize = (id: string) => {
    let data: t = {id: id};
    Lwt.return(data);
  };

  let compare = (x: t, y: t) => {
    String.compare(x.id, y.id);
  };
};

module Session = Morph_session.Make(SessionData);

let testSuite = () => (
  "Morph_session",
  [
    Alcotest.test_case(
      "gen_sid called twice with same secret returns 2 different ids",
      `Quick,
      _ => {
        let secret = "secret";
        let id1 = Session.gen_sid(secret);
        let id2 = Session.gen_sid(secret);
        print_endline(id1);
        print_endline(id2);
        Alcotest.(check(bool, "ids are different", id1 != id2, true));
      },
    ),
    Alcotest.test_case(
      "gen_sid always has the same length (88 chars)",
      `Quick,
      _ => {
        let secret = "secret";
        let start = 0;
        let finish = 1000;

        for (_ in start to finish) {
          let sid = Session.gen_sid(secret);
          Alcotest.(check(int, "has length 88", String.length(sid), 88));
        };
      },
    ),
    Alcotest.test_case(
      "gen_sid works with secret less than 16 chars",
      `Quick,
      _ => {
        let secret = "secret";
        let sid = Session.gen_sid(secret);
        Alcotest.(check(int, "has length 88", String.length(sid), 88));
      },
    ),
    Alcotest.test_case(
      "gen_sid works with secret exactly 16 chars",
      `Quick,
      _ => {
        let secret = "secret0987654321";
        let sid = Session.gen_sid(secret);
        Alcotest.(check(int, "has length 88", String.length(sid), 88));
      },
    ),
    Alcotest.test_case(
      "gen_sid works with secret greater than 16 chars, and non divisible",
      `Quick,
      _ => {
        let secret = "keep it secret, keep it safe";
        let sid = Session.gen_sid(secret);
        Alcotest.(check(int, "has length 88", String.length(sid), 88));
      },
    ),
    Alcotest.test_case(
      "gen_sid sid unsigns properly",
      `Quick,
      _ => {
        let secret = "keep it secret, keep it safe";
        let sid = Session.gen_sid(secret);
        let unsigned_sid = Session.unsign(sid, secret);
        let resigned_sid = Session.sign(unsigned_sid, secret);
        let re_unsigned_sid = Session.unsign(resigned_sid, secret);
        let unsigned_with_wrong_secret =
          Session.unsign(sid, "other secret bro");
        Alcotest.(
          check(
            bool,
            "signed and unsigned are different",
            sid != unsigned_sid,
            true,
          )
        );
        Alcotest.(check(string, "signs the same", resigned_sid, sid));
        Alcotest.(
          check(string, "unsigns the same", re_unsigned_sid, unsigned_sid)
        );
        Alcotest.(
          check(
            bool,
            "wrong secret unsignes a different value",
            unsigned_sid != unsigned_with_wrong_secret,
            true,
          )
        );
      },
    ),
  ],
);