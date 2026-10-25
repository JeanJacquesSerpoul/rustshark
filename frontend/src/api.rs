//! Passerelle vers les commandes Tauri (`window.__TAURI__`).

use leptos::task::spawn_local;
use serde::de::DeserializeOwned;
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], js_name = invoke, catch)]
    async fn tauri_invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"], js_name = listen, catch)]
    async fn tauri_listen(event: &str, handler: &Closure<dyn FnMut(JsValue)>) -> Result<JsValue, JsValue>;
}

#[derive(Serialize)]
pub struct NoArgs {}

fn js_error(e: JsValue) -> String {
    e.as_string()
        .or_else(|| js_sys::Reflect::get(&e, &"message".into()).ok().and_then(|m| m.as_string()))
        .unwrap_or_else(|| format!("{e:?}"))
}

/// Appelle une commande du backend et désérialise le résultat.
pub async fn call<A: Serialize, R: DeserializeOwned>(cmd: &str, args: &A) -> Result<R, String> {
    let ser = serde_wasm_bindgen::Serializer::json_compatible();
    let args = args.serialize(&ser).map_err(|e| e.to_string())?;
    let v = tauri_invoke(cmd, args).await.map_err(js_error)?;
    serde_wasm_bindgen::from_value(v).map_err(|e| e.to_string())
}

pub async fn call0<R: DeserializeOwned>(cmd: &str) -> Result<R, String> {
    call(cmd, &NoArgs {}).await
}

/// Écoute un événement émis par le backend.
pub fn listen<T: DeserializeOwned + 'static>(event: &'static str, f: impl Fn(T) + 'static) {
    let cb = Closure::<dyn FnMut(JsValue)>::new(move |ev: JsValue| {
        if let Ok(payload) = js_sys::Reflect::get(&ev, &"payload".into()) {
            if let Ok(v) = serde_wasm_bindgen::from_value::<T>(payload) {
                f(v);
            }
        }
    });
    spawn_local(async move {
        let _ = tauri_listen(event, &cb).await;
        cb.forget();
    });
}

pub fn tauri_available() -> bool {
    web_sys::window()
        .and_then(|w| js_sys::Reflect::get(&w, &"__TAURI__".into()).ok())
        .map(|v| !v.is_undefined())
        .unwrap_or(false)
}
