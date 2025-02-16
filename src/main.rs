use std::vec;

use actix_web::{cookie::{time::{Date, Duration, Month, OffsetDateTime, Time}, Cookie, SameSite}, get, App, HttpRequest, HttpResponse, HttpServer, Responder};
use openidconnect::{core::{CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata}, reqwest::{self, Client}, url::Url, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyAdditionalClaims, IdToken, IssuerUrl, Nonce, RedirectUrl, TokenResponse};

const HEADER_CT_HTML: &str = "text/html; charset=utf-8";
const NONCE_COOKIE: &str = "_nonce";
const STATE_COOKIE: &str = "_state";
const TOKEN_COOKIE: &str = "token";


fn redirect_without_cache(location: &str, cookies: &Vec<Cookie>) -> HttpResponse {
    let mut res = HttpResponse::MovedPermanently();


    for cookie in cookies {
        res.cookie(cookie.clone());
    }

    res
        .append_header(("Cache-Control", "no-cache"))
        .append_header(("Location", location))
        .finish()
}

async fn get_id_token(code: String) -> IdToken<EmptyAdditionalClaims, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm> {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should have been built");   

    let meta_data = CoreProviderMetadata::discover_async(
        IssuerUrl::new("http://localhost:8786/realms/Test".to_owned()).unwrap(), 
        &http_client
    ).await
    .unwrap();

    println!("Metadata reveived ...");
    println!("{meta_data:?}");

    let oidc_client = CoreClient::from_provider_metadata(
        meta_data,
        ClientId::new("rustclient".to_owned()),
        // for this test I hardcoded the secret, don't do that at home or in production :)
        Some(ClientSecret::new("bl9WKkAk0iGwOF5me4qSatrClrTy1u8h".to_owned()))
    )
    .set_redirect_uri(RedirectUrl::new("http://localhost:5454/sso".to_owned()).unwrap());


    let t = oidc_client
        .exchange_code(AuthorizationCode::new(code))
        .unwrap()
        .request_async(&http_client)
        .await.unwrap();

    let id_token = t.id_token().unwrap();

    id_token.clone()
}


async fn get_url_and_params() -> (Url, CsrfToken, Nonce) {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should have been built");   

    let meta_data = CoreProviderMetadata::discover_async(
        IssuerUrl::new("http://localhost:8786/realms/Test".to_owned()).unwrap(), 
        &http_client
    ).await
    .unwrap();

    println!("Metadata reveived ...");
    println!("{meta_data:?}");

    let oidc_client = CoreClient::from_provider_metadata(
        meta_data,
        ClientId::new("rustclient".to_owned()),
        // for this test I hardcoded the secret, don't do that at home or in production :)
        Some(ClientSecret::new("bl9WKkAk0iGwOF5me4qSatrClrTy1u8h".to_owned()))
    )
    .set_redirect_uri(RedirectUrl::new("http://localhost:5454/sso".to_owned()).unwrap());


    oidc_client.authorize_url(
        CoreAuthenticationFlow::AuthorizationCode, 
        || { CsrfToken::new("statevalue".to_owned())},
        || { Nonce::new("noncevalue".to_owned()) }
        // CsrfToken::new_random,
        // Nonce::new_random
    ).url()
}


async fn authentication_flow() -> HttpResponse {
    let (auth_url, state, nonce) = get_url_and_params().await;

    let state_cookie = Cookie::build(STATE_COOKIE, state.secret())
        // .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::minutes(5))
        .http_only(true)
        .finish();

    let nonce_cookie = Cookie::build(NONCE_COOKIE, nonce.secret())
        // .secure(true)
        .same_site(SameSite::Lax)
        .http_only(true)
        .finish();

    redirect_without_cache(&auth_url.to_string(), &vec![state_cookie, nonce_cookie])
}

#[get("/sso")]
async fn sso(req: HttpRequest) -> impl Responder {
    let state_cookie =  req.cookie(STATE_COOKIE).map(|c| c.value().to_owned()).unwrap_or(String::new());
    let mut nonce_cookie = req.cookie(NONCE_COOKIE).unwrap();
    nonce_cookie.set_same_site(SameSite::Lax);

    if state_cookie == "" {
        println!("State cookie is EMPTY");
        return HttpResponse::Unauthorized().finish();
    }

    // ToDo: use Query<OidcParams>
    let query_params = req.query_string().split("&")
        .filter_map(|param| {
            let mut parts = param.split("=");
            Some((parts.next()?.to_owned(), parts.next().unwrap_or("").to_owned()))
        })
        .collect::<Vec<(String, String)>>();

    // println!("(/sso) -> PARAMS");
    // for p in query_params {
    //     println!("{} = {}", p.0, p.1);
    // }

    if let Some(state) = query_params.iter().find(|param| param.0 == "state").map(|s| s.1.to_owned()) {
        if state == state_cookie {
            if let Some(code) = query_params.iter().find(|param| param.0 == "code").map(|s| s.1.to_owned()) {
                let id_token = get_id_token(code).await;
                let token_str = id_token.to_string();
                println!("Got an ID  Token: {}", token_str);

                let token_cookie = Cookie::build(TOKEN_COOKIE, token_str)
                .same_site(SameSite::Lax)
                .http_only(true)
                .finish();


                return redirect_without_cache("/profile", &vec![nonce_cookie, token_cookie]);
            }
        }
    }

    println!("Could not retrieve token :(");
    HttpResponse::Unauthorized().finish()
}

#[get("/profile")]
async fn profile(req: HttpRequest) -> impl Responder {
    // Step 1: check cookie
    if let Some(_token_cookieealm) = req.cookie(TOKEN_COOKIE) {
        // validate token
        
        HttpResponse::Ok()
            .content_type(HEADER_CT_HTML)
            .body("<h1>My Profile</h1><p><strong>ToDo</strong>: User infos 🥳</p>")
    } else {
        println!("Do authentication flow");
        authentication_flow().await
    }
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type(HEADER_CT_HTML)
        .body("<h1>The public index site 🤗</h1>")
}



#[get("/logout")]
async fn logout() -> impl Responder {
    let t = OffsetDateTime::new_utc(Date::from_calendar_date(1970, Month::January, 1).unwrap(), Time::from_hms(0, 0, 0).unwrap());
    let nonce = Cookie::build(NONCE_COOKIE, "")
        .expires(t)
        .finish();
    let token = Cookie::build(TOKEN_COOKIE, "")
        .expires(t)
        .finish();

    redirect_without_cache("http://localhost:8786/realms/Test/protocol/openid-connect/logout?redirect_uri=%2F", &vec![nonce, token])
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(profile)
            .service(sso)
            .service(index)
            .service(logout)
    })
    .bind(("127.0.0.1", 5454))?
    .run()
    .await
}