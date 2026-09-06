// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Redirect,

    Index,

    Events,

    Api(String),
    NotFound,
}

pub fn classify(base: &str, path: &str) -> Route {
    let path = path.split('?').next().unwrap_or(path);

    let path = normalize(path);

    let Some(rest) = path.strip_prefix(base) else {
        return Route::NotFound;
    };

    if !rest.is_empty() && !rest.starts_with('/') {
        return Route::NotFound;
    }

    match rest {
        "" => {
            if base.is_empty() {
                Route::Index
            } else {
                Route::Redirect
            }
        }
        "/" => Route::Index,
        "/api/events" => Route::Events,
        r => match r.strip_prefix("/api/") {
            Some(sub) if !sub.is_empty() => Route::Api(sub.to_string()),
            _ => Route::NotFound,
        },
    }
}

fn normalize(path: &str) -> String {
    let mut out = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let joined = format!("/{}", out.join("/"));

    if path.ends_with('/') && joined != "/" {
        format!("{joined}/")
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "/stmp2log";

    #[test]
    fn serves_the_page_at_the_prefix() {
        assert_eq!(classify(BASE, "/stmp2log/"), Route::Index);
        assert_eq!(classify(BASE, "/stmp2log"), Route::Redirect);
    }

    #[test]
    fn routes_api_calls() {
        assert_eq!(
            classify(BASE, "/stmp2log/api/messages"),
            Route::Api("messages".into())
        );
        assert_eq!(
            classify(BASE, "/stmp2log/api/messages/42"),
            Route::Api("messages/42".into())
        );
        assert_eq!(
            classify(BASE, "/stmp2log/api/auth/login"),
            Route::Api("auth/login".into())
        );
        assert_eq!(classify(BASE, "/stmp2log/api/events"), Route::Events);
    }

    #[test]
    fn the_query_string_is_not_part_of_the_route() {
        assert_eq!(
            classify(BASE, "/stmp2log/api/messages?limit=50&q=%E6%B8%A9"),
            Route::Api("messages".into())
        );
    }

    #[test]
    fn everything_outside_the_prefix_is_invisible() {
        for p in [
            "/",
            "/index.html",
            "/api/messages",
            "/favicon.ico",
            "/admin",
        ] {
            assert_eq!(classify(BASE, p), Route::NotFound, "path {p}");
        }
    }

    #[test]
    fn a_prefix_that_is_only_a_string_prefix_does_not_match() {
        assert_eq!(classify(BASE, "/stmp2logger/api/messages"), Route::NotFound);
        assert_eq!(classify(BASE, "/stmp2log2/"), Route::NotFound);
    }

    #[test]
    fn duplicate_slashes_and_dot_segments_cannot_smuggle_past_the_prefix() {
        assert_eq!(
            classify(BASE, "//stmp2log//api//messages"),
            Route::Api("messages".into())
        );
        assert_eq!(
            classify(BASE, "/stmp2log/./api/messages"),
            Route::Api("messages".into())
        );
        assert_eq!(
            classify(BASE, "/other/../stmp2log/api/messages"),
            Route::Api("messages".into())
        );

        assert_eq!(classify(BASE, "/stmp2log/../etc/passwd"), Route::NotFound);
    }

    #[test]
    fn an_empty_base_mounts_at_the_root() {
        assert_eq!(classify("", "/"), Route::Index);
        assert_eq!(classify("", "/api/messages"), Route::Api("messages".into()));
        assert_eq!(classify("", "/api/events"), Route::Events);
        assert_eq!(classify("", "/nope"), Route::NotFound);
    }

    #[test]
    fn a_bare_api_path_is_not_a_route() {
        assert_eq!(classify(BASE, "/stmp2log/api/"), Route::NotFound);
        assert_eq!(classify(BASE, "/stmp2log/api"), Route::NotFound);
    }

    #[test]
    fn unknown_paths_under_the_prefix_are_not_the_page() {
        assert_eq!(classify(BASE, "/stmp2log/assets/app.js"), Route::NotFound);
    }
}
