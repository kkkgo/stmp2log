// Copyright (c) 2026, https://blog.03k.org. All rights reserved.
use serde::{Deserialize, Serialize};

use crate::http;
use crate::sign;

#[derive(Debug, Clone, Default)]
pub struct Payload {
    pub title: String,
    pub body: String,

    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[derive(Default)]
pub enum NtfyAuth {
    #[default]
    None,
    UsernamePassword {
        username: String,
        password: String,
    },
    AccessToken {
        token: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Channel {
    Ntfy {
        #[serde(default = "ntfy_default_server")]
        server: String,
        topic: String,
        #[serde(default = "ntfy_default_priority")]
        priority: u8,
        #[serde(default)]
        auth: NtfyAuth,
        #[serde(default)]
        tags: Vec<String>,
    },
    Bark {
        endpoint: String,
        #[serde(default)]
        group: String,
        #[serde(default)]
        sound: String,

        #[serde(default)]
        level: String,
    },
    Telegram {
        #[serde(default = "telegram_default_server")]
        server: String,
        token: String,
        chat_id: String,
        #[serde(default)]
        thread_id: String,
        #[serde(default)]
        silent: bool,
    },
    #[serde(rename = "dingtalk")]
    DingTalk {
        webhook: String,

        #[serde(default)]
        secret: String,
        #[serde(default)]
        at_mobiles: Vec<String>,
        #[serde(default)]
        at_all: bool,
    },
    Feishu {
        webhook: String,

        #[serde(default)]
        secret: String,
    },
    #[serde(rename = "wecom")]
    WeCom {
        key: String,
        #[serde(default)]
        mentioned_mobiles: Vec<String>,
    },
    #[serde(rename = "serverchan")]
    ServerChan { sendkey: String },
    #[serde(rename = "aliyun_sms")]
    AliyunSms {
        access_key_id: String,
        access_key_secret: String,

        phone_numbers: String,
        sign_name: String,
        template_code: String,
    },
}

fn ntfy_default_server() -> String {
    "https://ntfy.sh".into()
}

fn ntfy_default_priority() -> u8 {
    5
}

fn telegram_default_server() -> String {
    "https://api.telegram.org".into()
}

impl Channel {
    pub fn kind(&self) -> &'static str {
        match self {
            Channel::Ntfy { .. } => "ntfy",
            Channel::Bark { .. } => "bark",
            Channel::Telegram { .. } => "telegram",
            Channel::DingTalk { .. } => "dingtalk",
            Channel::Feishu { .. } => "feishu",
            Channel::WeCom { .. } => "wecom",
            Channel::ServerChan { .. } => "serverchan",
            Channel::AliyunSms { .. } => "aliyun_sms",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Built {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl Built {
    fn json(method: &'static str, url: String, value: serde_json::Value) -> Self {
        Self {
            method,
            url,
            headers: vec![("Content-Type", "application/json".to_string())],
            body: serde_json::to_vec(&value).unwrap_or_default(),
        }
    }
}

pub fn build(ch: &Channel, p: &Payload, now_ms: i64) -> Built {
    match ch {
        Channel::Ntfy {
            server,
            topic,
            priority,
            auth,
            tags,
        } => {
            let mut headers = vec![("Content-Type", "application/json".to_string())];
            match auth {
                NtfyAuth::None => {}
                NtfyAuth::UsernamePassword { username, password } => {
                    use base64::Engine;
                    let raw = format!("{username}:{password}");
                    let enc = base64::engine::general_purpose::STANDARD.encode(raw);
                    headers.push(("Authorization", format!("Basic {enc}")));
                }
                NtfyAuth::AccessToken { token } => {
                    headers.push(("Authorization", format!("Bearer {token}")));
                }
            }
            let mut body = serde_json::json!({
                "topic": topic,
                "title": p.title,
                "message": p.body,
                "priority": priority,
            });
            if !tags.is_empty() {
                body["tags"] = serde_json::json!(tags);
            }
            if let Some(u) = &p.url {
                body["actions"] = serde_json::json!([{
                    "action": "view", "label": "Open stmp2log", "url": u
                }]);
            }
            Built {
                method: "POST",

                url: server.trim_end_matches('/').to_string(),
                headers,
                body: serde_json::to_vec(&body).unwrap_or_default(),
            }
        }

        Channel::Bark {
            endpoint,
            group,
            sound,
            level,
        } => {
            let mut body = serde_json::json!({
                "title": p.title,
                "body": p.body,
            });
            if !group.is_empty() {
                body["group"] = group.as_str().into();
            }
            if !sound.is_empty() {
                body["sound"] = sound.as_str().into();
            }
            if !level.is_empty() {
                body["level"] = level.as_str().into();
            }
            if let Some(u) = &p.url {
                body["url"] = u.as_str().into();
            }
            Built::json("POST", endpoint.trim_end_matches('/').to_string(), body)
        }

        Channel::Telegram {
            server,
            token,
            chat_id,
            thread_id,
            silent,
        } => {
            let mut body = serde_json::json!({
                "chat_id": chat_id,
                "text": join_title_body(p),
                "disable_notification": silent,
                "link_preview_options": { "is_disabled": true },
            });
            if !thread_id.is_empty() {
                body["message_thread_id"] = thread_id.as_str().into();
            }
            Built::json(
                "POST",
                format!("{}/bot{token}/sendMessage", server.trim_end_matches('/')),
                body,
            )
        }

        Channel::DingTalk {
            webhook,
            secret,
            at_mobiles,
            at_all,
        } => {
            let mut url = webhook.clone();
            if !secret.is_empty() {
                let sig = sign::dingtalk(now_ms, secret);

                let sep = if url.contains('?') { '&' } else { '?' };
                url = format!(
                    "{url}{sep}timestamp={now_ms}&sign={}",
                    sign::urlencode(&sig)
                );
            }
            let body = serde_json::json!({
                "msgtype": "text",
                "text": { "content": join_title_body(p) },
                "at": { "isAtAll": at_all, "atMobiles": at_mobiles },
            });
            Built::json("POST", url, body)
        }

        Channel::Feishu { webhook, secret } => {
            let mut body = serde_json::json!({
                "msg_type": "text",
                "content": { "text": join_title_body(p) },
            });
            if !secret.is_empty() {
                let ts = now_ms / 1000;
                body["timestamp"] = ts.to_string().into();
                body["sign"] = sign::feishu(ts, secret).into();
            }
            Built::json("POST", webhook.clone(), body)
        }

        Channel::WeCom {
            key,
            mentioned_mobiles,
        } => {
            let url = if key.starts_with("http://") || key.starts_with("https://") {
                key.clone()
            } else {
                format!("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={key}")
            };
            let mut text = serde_json::json!({ "content": join_title_body(p) });
            if !mentioned_mobiles.is_empty() {
                text["mentioned_mobile_list"] = serde_json::json!(mentioned_mobiles);
            }
            Built::json(
                "POST",
                url,
                serde_json::json!({ "msgtype": "text", "text": text }),
            )
        }

        Channel::ServerChan { sendkey } => {
            let url = match sctp_uid(sendkey) {
                Some(uid) => format!("https://{uid}.push.ft07.com/send/{sendkey}.send"),
                None => format!("https://sctapi.ftqq.com/{sendkey}.send"),
            };
            Built::json(
                "POST",
                url,
                serde_json::json!({ "title": p.title, "desp": p.body }),
            )
        }

        Channel::AliyunSms {
            access_key_id,
            access_key_secret,
            phone_numbers,
            sign_name,
            template_code,
        } => {
            let template_param = serde_json::json!({
                "subject": truncate(&p.title, 20),
                "time": iso8601(now_ms),
            })
            .to_string();

            let mut params: Vec<(String, String)> = [
                ("AccessKeyId", access_key_id.as_str()),
                ("Action", "SendSms"),
                ("Format", "JSON"),
                ("PhoneNumbers", phone_numbers.as_str()),
                ("SignName", sign_name.as_str()),
                ("SignatureMethod", "HMAC-SHA1"),
                ("SignatureVersion", "1.0"),
                ("TemplateCode", template_code.as_str()),
                ("Version", "2017-05-25"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
            params.push(("SignatureNonce".into(), nonce(now_ms)));
            params.push(("Timestamp".into(), iso8601(now_ms)));
            params.push(("TemplateParam".into(), template_param));

            let signature = sign::aliyun(&params, access_key_secret);
            params.push(("Signature".into(), signature));

            let form = params
                .iter()
                .map(|(k, v)| format!("{}={}", sign::rfc3986(k), sign::rfc3986(v)))
                .collect::<Vec<_>>()
                .join("&");

            Built {
                method: "POST",

                url: "https://dysmsapi.aliyuncs.com/".into(),
                headers: vec![(
                    "Content-Type",
                    "application/x-www-form-urlencoded".to_string(),
                )],
                body: form.into_bytes(),
            }
        }
    }
}

pub fn check(ch: &Channel, resp: &http::Response) -> Result<(), String> {
    let json = resp.json();
    let field_err = |code_key: &str, msg_key: &str| -> Option<String> {
        let code = json.get(code_key)?;
        let ok = code.as_i64() == Some(0);
        if ok {
            return None;
        }
        let msg = json
            .get(msg_key)
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        Some(format!("{code_key} {code}: {msg}"))
    };

    match ch {
        Channel::DingTalk { .. } | Channel::WeCom { .. } => {
            if let Some(e) = field_err("errcode", "errmsg") {
                return Err(e);
            }
        }
        Channel::Feishu { .. } => {
            if let Some(e) = field_err("code", "msg") {
                return Err(e);
            }

            if let Some(sc) = json.get("StatusCode").and_then(|v| v.as_i64()) {
                if sc != 0 {
                    return Err(format!("StatusCode {sc}"));
                }
            }
        }
        Channel::ServerChan { .. } => {
            if let Some(e) = field_err("code", "message").or_else(|| field_err("code", "error")) {
                return Err(e);
            }
        }
        Channel::AliyunSms { .. } => {
            if let Some(code) = json.get("Code").and_then(|v| v.as_str()) {
                if code != "OK" {
                    let msg = json
                        .get("Message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown error");
                    return Err(format!("{code}: {msg}"));
                }
            }
        }

        Channel::Ntfy { .. } | Channel::Bark { .. } | Channel::Telegram { .. } => {}
    }

    if !(200..300).contains(&resp.status) {
        let hint = resp.text();
        let hint = hint.trim();
        return Err(if hint.is_empty() {
            format!("HTTP {}", resp.status)
        } else {
            format!("HTTP {}: {}", resp.status, truncate(hint, 200))
        });
    }
    Ok(())
}

fn sctp_uid(key: &str) -> Option<String> {
    let rest = key
        .strip_prefix("sctp")
        .or_else(|| key.strip_prefix("SCTP"))?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let after = &rest[digits.len()..];
    if after.starts_with('t') || after.starts_with('T') {
        Some(digits)
    } else {
        None
    }
}

fn join_title_body(p: &Payload) -> String {
    if p.title.trim().is_empty() {
        p.body.clone()
    } else if p.body.trim().is_empty() {
        p.title.clone()
    } else {
        format!("{}\n{}", p.title, p.body)
    }
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars().take(max_chars).collect()
}

fn iso8601(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn nonce(now_ms: i64) -> String {
    let mut r = [0u8; 8];

    let _ = getrandom::getrandom(&mut r);
    format!("{now_ms}{}", u64::from_le_bytes(r))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_788_353_161_000;

    fn payload() -> Payload {
        Payload {
            title: "[温度告警] UPS-01".into(),
            body: "Sensor 3 reports 48C".into(),
            url: Some("http://10.0.0.2:8025/stmp2log/#/?id=42".into()),
        }
    }

    fn body_json(b: &Built) -> serde_json::Value {
        serde_json::from_slice(&b.body).expect("request body must be valid JSON")
    }

    #[test]
    fn ntfy_posts_to_the_root_with_the_topic_in_the_body() {
        let ch = Channel::Ntfy {
            server: "https://ntfy.sh".into(),
            topic: "my-alerts".into(),
            priority: 4,
            auth: NtfyAuth::None,
            tags: vec!["rotating_light".into()],
        };
        let b = build(&ch, &payload(), NOW);
        assert_eq!(b.method, "POST");
        assert_eq!(b.url, "https://ntfy.sh");
        let j = body_json(&b);
        assert_eq!(j["topic"], "my-alerts");
        assert_eq!(j["priority"], 4);
        assert_eq!(j["title"], "[温度告警] UPS-01");
        assert_eq!(j["tags"][0], "rotating_light");
        assert_eq!(j["actions"][0]["action"], "view");
    }

    #[test]
    fn ntfy_self_hosted_server_keeps_its_port_and_drops_a_trailing_slash() {
        let ch = Channel::Ntfy {
            server: "http://10.0.0.9:8080/".into(),
            topic: "t".into(),
            priority: 5,
            auth: NtfyAuth::None,
            tags: vec![],
        };
        assert_eq!(build(&ch, &payload(), NOW).url, "http://10.0.0.9:8080");
    }

    #[test]
    fn ntfy_auth_headers() {
        let basic = Channel::Ntfy {
            server: ntfy_default_server(),
            topic: "t".into(),
            priority: 5,
            auth: NtfyAuth::UsernamePassword {
                username: "u".into(),
                password: "p".into(),
            },
            tags: vec![],
        };
        let h = build(&basic, &payload(), NOW).headers;
        assert!(h.contains(&("Authorization", "Basic dTpw".to_string())));

        let token = Channel::Ntfy {
            server: ntfy_default_server(),
            topic: "t".into(),
            priority: 5,
            auth: NtfyAuth::AccessToken {
                token: "tk_x".into(),
            },
            tags: vec![],
        };
        let h = build(&token, &payload(), NOW).headers;
        assert!(h.contains(&("Authorization", "Bearer tk_x".to_string())));
    }

    #[test]
    fn bark_uses_the_json_api_so_slashes_in_the_title_survive() {
        let ch = Channel::Bark {
            endpoint: "https://api.day.app/DEVICEKEY/".into(),
            group: "stmp2log".into(),
            sound: "alarm".into(),
            level: "timeSensitive".into(),
        };
        let mut p = payload();
        p.title = "/dev/sda failed".into();
        let b = build(&ch, &p, NOW);
        assert_eq!(b.url, "https://api.day.app/DEVICEKEY");
        let j = body_json(&b);
        assert_eq!(j["title"], "/dev/sda failed");
        assert_eq!(j["group"], "stmp2log");
        assert_eq!(j["level"], "timeSensitive");
    }

    #[test]
    fn telegram_builds_the_bot_endpoint() {
        let ch = Channel::Telegram {
            server: telegram_default_server(),
            token: "123:ABC".into(),
            chat_id: "-100777".into(),
            thread_id: String::new(),
            silent: true,
        };
        let b = build(&ch, &payload(), NOW);
        assert_eq!(b.url, "https://api.telegram.org/bot123:ABC/sendMessage");
        let j = body_json(&b);
        assert_eq!(j["chat_id"], "-100777");
        assert_eq!(j["disable_notification"], true);
        assert!(j["text"].as_str().unwrap().contains("温度告警"));
        assert!(
            j.get("message_thread_id").is_none(),
            "empty thread id must be omitted"
        );
    }

    #[test]
    fn dingtalk_appends_the_signature_with_an_ampersand() {
        let ch = Channel::DingTalk {
            webhook: "https://oapi.dingtalk.com/robot/send?access_token=TOKEN".into(),
            secret: "SECabc123".into(),
            at_mobiles: vec!["13800138000".into()],
            at_all: false,
        };
        let b = build(&ch, &payload(), NOW);
        assert!(
            b.url
                .contains("?access_token=TOKEN&timestamp=1788353161000&sign=")
        );
        assert!(
            b.url
                .contains("5OaY8IqHiwWhu51heCgdSRr%2BarSGrymRnTobQyLkoO4%3D"),
            "url was {}",
            b.url
        );
        let j = body_json(&b);
        assert_eq!(j["msgtype"], "text");
        assert_eq!(j["at"]["atMobiles"][0], "13800138000");
    }

    #[test]
    fn dingtalk_without_a_secret_leaves_the_url_alone() {
        let ch = Channel::DingTalk {
            webhook: "https://oapi.dingtalk.com/robot/send?access_token=T".into(),
            secret: String::new(),
            at_mobiles: vec![],
            at_all: true,
        };
        let b = build(&ch, &payload(), NOW);
        assert_eq!(b.url, "https://oapi.dingtalk.com/robot/send?access_token=T");
        assert_eq!(body_json(&b)["at"]["isAtAll"], true);
    }

    #[test]
    fn feishu_puts_the_signature_in_the_body_with_a_seconds_timestamp() {
        let ch = Channel::Feishu {
            webhook: "https://open.feishu.cn/open-apis/bot/v2/hook/xyz".into(),
            secret: "FSsecret456".into(),
        };
        let j = body_json(&build(&ch, &payload(), NOW));
        assert_eq!(
            j["timestamp"], "1788353161",
            "feishu wants seconds, not milliseconds"
        );
        assert_eq!(j["sign"], "9cm362w5O7lGHftF1F9tcWzWRMLrsLb1mfwjKp47Mlc=");
        assert_eq!(j["msg_type"], "text");
    }

    #[test]
    fn feishu_without_a_secret_omits_the_signature_fields() {
        let ch = Channel::Feishu {
            webhook: "https://open.feishu.cn/x".into(),
            secret: String::new(),
        };
        let j = body_json(&build(&ch, &payload(), NOW));
        assert!(j.get("sign").is_none());
        assert!(j.get("timestamp").is_none());
    }

    #[test]
    fn wecom_accepts_either_a_bare_key_or_a_full_webhook() {
        let bare = Channel::WeCom {
            key: "abc-123".into(),
            mentioned_mobiles: vec![],
        };
        assert_eq!(
            build(&bare, &payload(), NOW).url,
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc-123"
        );

        let full = Channel::WeCom {
            key: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc-123".into(),
            mentioned_mobiles: vec!["13800138000".into()],
        };
        let b = build(&full, &payload(), NOW);
        assert_eq!(
            b.url,
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc-123"
        );
        assert_eq!(
            body_json(&b)["text"]["mentioned_mobile_list"][0],
            "13800138000"
        );
    }

    #[test]
    fn serverchan_routes_v3_keys_to_the_uid_host() {
        let v3 = Channel::ServerChan {
            sendkey: "sctp1234tABCDEFG".into(),
        };
        assert_eq!(
            build(&v3, &payload(), NOW).url,
            "https://1234.push.ft07.com/send/sctp1234tABCDEFG.send"
        );

        let legacy = Channel::ServerChan {
            sendkey: "SCT123456xyz".into(),
        };
        assert_eq!(
            build(&legacy, &payload(), NOW).url,
            "https://sctapi.ftqq.com/SCT123456xyz.send"
        );
    }

    #[test]
    fn sctp_uid_only_matches_the_real_shape() {
        assert_eq!(sctp_uid("sctp999tKEY").as_deref(), Some("999"));
        assert_eq!(sctp_uid("SCT123456"), None, "legacy keys must not match");
        assert_eq!(sctp_uid("sctpNOTDIGITStKEY"), None);
        assert_eq!(
            sctp_uid("sctp123KEY"),
            None,
            "the digits must be followed by 't'"
        );
    }

    #[test]
    fn aliyun_sends_a_signed_form_body_over_https() {
        let ch = Channel::AliyunSms {
            access_key_id: "LTAItest".into(),
            access_key_secret: "SECRETtest".into(),
            phone_numbers: "13800138000".into(),
            sign_name: "test".into(),
            template_code: "SMS_1".into(),
        };
        let b = build(&ch, &payload(), NOW);
        assert_eq!(b.url, "https://dysmsapi.aliyuncs.com/");
        assert_eq!(
            b.headers[0].1, "application/x-www-form-urlencoded",
            "the RPC API is form-encoded, not JSON"
        );
        let form = String::from_utf8(b.body).unwrap();
        assert!(form.contains("Signature="));
        assert!(form.contains("Action=SendSms"));
        assert!(form.contains("Timestamp=2026-09-02T12%3A46%3A01Z"));
        assert!(
            !form.contains('+'),
            "RFC 3986 encoding means spaces are %20, never +"
        );
    }

    #[test]
    fn iso8601_matches_the_aliyun_format() {
        assert_eq!(iso8601(1_788_353_161_000), "2026-09-02T12:46:01Z");
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_709_164_800_000), "2024-02-29T00:00:00Z");
    }

    fn resp(status: u16, body: &str) -> http::Response {
        http::Response {
            status,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn dingtalk_http_200_with_an_errcode_is_a_failure() {
        let ch = Channel::DingTalk {
            webhook: "x".into(),
            secret: String::new(),
            at_mobiles: vec![],
            at_all: false,
        };
        let err = check(
            &ch,
            &resp(200, r#"{"errcode":300005,"errmsg":"token is not exist"}"#),
        )
        .unwrap_err();
        assert!(err.contains("token is not exist"), "err was {err}");
        assert!(check(&ch, &resp(200, r#"{"errcode":0,"errmsg":"ok"}"#)).is_ok());
    }

    #[test]
    fn feishu_http_200_with_a_nonzero_code_is_a_failure() {
        let ch = Channel::Feishu {
            webhook: "x".into(),
            secret: String::new(),
        };
        let err = check(
            &ch,
            &resp(200, r#"{"code":19001,"msg":"param invalid: incoming webhook access token invalid","data":{}}"#),
        )
        .unwrap_err();
        assert!(err.contains("19001"), "err was {err}");
        assert!(check(&ch, &resp(200, r#"{"code":0,"msg":"success"}"#)).is_ok());
    }

    #[test]
    fn wecom_http_200_with_an_errcode_is_a_failure() {
        let ch = Channel::WeCom {
            key: "x".into(),
            mentioned_mobiles: vec![],
        };
        let err = check(
            &ch,
            &resp(200, r#"{"errcode":93000,"errmsg":"invalid webhook url"}"#),
        )
        .unwrap_err();
        assert!(err.contains("93000"));
        assert!(check(&ch, &resp(200, r#"{"errcode":0,"errmsg":"ok"}"#)).is_ok());
    }

    #[test]
    fn serverchan_v3_http_200_with_a_code_is_a_failure() {
        let ch = Channel::ServerChan {
            sendkey: "sctp1t".into(),
        };
        let err = check(
            &ch,
            &resp(200, r#"{"error":"sendkey not found","code":10003}"#),
        )
        .unwrap_err();
        assert!(err.contains("10003"), "err was {err}");
        assert!(check(&ch, &resp(200, r#"{"code":0,"message":""}"#)).is_ok());
    }

    #[test]
    fn aliyun_checks_the_code_string_not_the_status() {
        let ch = Channel::AliyunSms {
            access_key_id: "a".into(),
            access_key_secret: "b".into(),
            phone_numbers: "c".into(),
            sign_name: "d".into(),
            template_code: "e".into(),
        };
        let err = check(
            &ch,
            &resp(
                400,
                r#"{"Code":"SignatureDoesNotMatch","Message":"bad signature"}"#,
            ),
        )
        .unwrap_err();
        assert!(err.contains("SignatureDoesNotMatch"));
        assert!(check(&ch, &resp(200, r#"{"Code":"OK","Message":"OK"}"#)).is_ok());
    }

    #[test]
    fn status_code_providers_fail_on_non_2xx() {
        let ch = Channel::Ntfy {
            server: ntfy_default_server(),
            topic: "t".into(),
            priority: 5,
            auth: NtfyAuth::None,
            tags: vec![],
        };
        let err = check(
            &ch,
            &resp(
                400,
                r#"{"code":40009,"error":"invalid request: topic invalid"}"#,
            ),
        )
        .unwrap_err();
        assert!(err.contains("400"), "err was {err}");
        assert!(check(&ch, &resp(200, r#"{"id":"abc"}"#)).is_ok());
    }

    #[test]
    fn a_non_json_error_page_still_produces_a_useful_message() {
        let ch = Channel::Telegram {
            server: telegram_default_server(),
            token: "t".into(),
            chat_id: "c".into(),
            thread_id: String::new(),
            silent: false,
        };
        let err = check(&ch, &resp(502, "<html>Bad Gateway</html>")).unwrap_err();
        assert!(err.contains("502"));
        assert!(err.contains("Bad Gateway"));
    }

    #[test]
    fn channels_round_trip_through_json() {
        let channels = vec![
            Channel::Ntfy {
                server: ntfy_default_server(),
                topic: "t".into(),
                priority: 5,
                auth: NtfyAuth::AccessToken { token: "x".into() },
                tags: vec![],
            },
            Channel::DingTalk {
                webhook: "w".into(),
                secret: "s".into(),
                at_mobiles: vec![],
                at_all: false,
            },
            Channel::AliyunSms {
                access_key_id: "a".into(),
                access_key_secret: "b".into(),
                phone_numbers: "c".into(),
                sign_name: "d".into(),
                template_code: "e".into(),
            },
        ];
        for ch in channels {
            let json = serde_json::to_string(&ch).unwrap();
            assert_eq!(serde_json::from_str::<Channel>(&json).unwrap(), ch);
            assert!(
                json.contains(&format!(r#""type":"{}""#, ch.kind())),
                "{json}"
            );
        }
    }

    #[test]
    fn optional_channel_fields_have_defaults_so_old_configs_keep_loading() {
        let ch: Channel = serde_json::from_str(r#"{"type":"ntfy","topic":"t"}"#).unwrap();
        match ch {
            Channel::Ntfy {
                server,
                priority,
                auth,
                ..
            } => {
                assert_eq!(server, "https://ntfy.sh");
                assert_eq!(priority, 5);
                assert_eq!(auth, NtfyAuth::None);
            }
            _ => panic!("wrong variant"),
        }
    }
}
