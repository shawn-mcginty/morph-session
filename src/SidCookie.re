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

let set = (name, sid, max_age, res: Morph_core.Response.t) => {
  let set_cookie_key = "Set-Cookie";
  let max_age_str = string_of_float(max_age);
  // remove the . at the end of the float
  let expiry = String.sub(max_age_str, 0, String.length(max_age_str) - 2);

  Morph_core.Response.add_header(
    (set_cookie_key, name ++ "=" ++ sid ++ "; Max-Age=" ++ expiry ++ ";"),
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

let has_set_cookie = (name, res: Morph_core.Response.t) => {
  let set_cookie_key = "Set-Cookie";
  let name_len = String.length(name);
  let existing_header =
    List.find_opt(
      ((h_key, h_val)) =>
        if (h_key == set_cookie_key) {
          if (String.sub(h_val, 0, name_len) == name) {
            true;
          } else {
            false;
          };
        } else {
          false;
        },
      res.headers,
    );
  switch (existing_header) {
  | Some(_) => true
  | None => false
  };
};