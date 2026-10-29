# httpsig-diff

Arnés diferencial de HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.txt)) entre crates de Rust: el mismo request firmado pasa por cada verificador y se compara el veredicto con el que espera el RFC.

Differential harness for HTTP Message Signatures (RFC 9421) across Rust crates: the same signed request goes through every verifier, and each verdict is compared with what the RFC expects.

> **ES** primero · **EN** abajo. Nivel de verificación: **B**.

---

## ES

### Qué se compara

| Implementación | Versión | Cómo se llama |
|---|---|---|
| [`web-bot-auth`](https://crates.io/api/v1/crates/web-bot-auth) (Cloudflare) | 0.7.0 | `MessageVerifier::parse` + `verify` |
| [`wimsey-httpsig`](https://crates.io/api/v1/crates/wimsey-httpsig) | 0.9.0 | `verify`, perfil WIMSE apagado |
| [`aauth-httpsig`](https://crates.io/api/v1/crates/aauth-httpsig) | 0.1.2 | `prepare_verification` + `verify` |
| `reference` (`src/reference.rs`) | — | escrita desde el RFC; control positivo |

Todas las firmas usan la clave `test-key-ed25519` del Apéndice B.1.4.

**Advertencia sobre `web-bot-auth`:** el crate no deriva `@method`, `@path`, `@query`, etc.; se los pide al integrador (`SignedMessage::lookup_component`). El adaptador le responde con la derivación de la referencia. Por eso, para `web-bot-auth`, la matriz prueba la parte propia del crate (parseo de los campos, label, combinación de líneas repetidas, serialización de `@signature-params`, verificación) y **no** su derivación de componentes, que no existe.

### Corpus (56 casos, prerregistrado en [`PREREGISTRO.md`](PREREGISTRO.md))

- 5 vectores del Apéndice B.2: B.2.6 con su firma Ed25519 original; B.2.1, B.2.2, B.2.3 y B.2.5 (RSA-PSS / HMAC en el RFC) re-firmados con `test-key-ed25519` sobre la base impresa en el RFC, de modo que aceptar ⇔ reconstruir exactamente esa base. B.2.4 (respuesta) no está.
- 21 válidos (`V*`): rechazarlos es un **rechazo espurio**.
- 23 alterados después de firmar (`T*`): aceptarlos es una **aceptación indebida**. Incluye dos controles negativos (`T20` firma alterada, `T21` otra clave).
- 7 de parseo (`P*`).

Cada caso lleva el veredicto esperado y la sección que lo decide; 6 son `ambiguous` y sólo cuentan como divergencia.

### Resultados

Reproducir (determinista; el CI exige la misma salida):

```sh
cargo run --release --bin httpsig-diff -- --csv results/matrix.csv --json results/summary.json
```

Matriz completa con el texto de error de cada crate: [`results/matrix.csv`](results/matrix.csv). Resumen: [`results/summary.json`](results/summary.json).

| | reference | web-bot-auth | wimsey-httpsig | aauth-httpsig |
|---|---|---|---|---|
| Apéndice B aceptados (de 5) | 5 | 5 | 4 | 3 |
| Coincide con el RFC (de 50 casos decididos) | 50 | 47 | 42 | 34 |
| Rechazos espurios | 0 | 2 | 7 | 10 |
| Aceptaciones indebidas | 0 | 1 | 1 | 6 |

Divergencias entre los 3 crates: **23 de 56 casos**. Controles negativos `T20` y `T21`: rechazados por las 4 implementaciones.

### Hallazgos

Aceptaciones indebidas:

| Caso | Crate(s) | Qué pasa | Sección |
|---|---|---|---|
| `T11` | aauth | Firmado `?q=it%27s`, llega `?q=it's`: acepta. Construye `@query` con el parser `url`, que re-codifica `'` en la query; dos queries distintas dan la misma base. | 9421 §2.2.7 |
| `T10` | aauth | Firmado `/transfer`, llega `/x/../transfer`: acepta (el parser `url` elimina dot segments). Ver la nota post-hoc abajo. | 9421 §2.2.6 |
| `T16` | web-bot-auth, aauth | `alg="rsa-pss-sha512"` en Signature-Input y clave Ed25519: aceptan. El RFC exige fallar si el algoritmo no coincide. El impacto práctico es bajo porque la clave fija Ed25519. | 9421 §3.2 paso 6.5 |
| `T18` | wimsey, aauth | El mismo componente cubierto dos veces: aceptan; el RFC exige error. | 9421 §2.5 paso 2.1 |
| `P01` | aauth | Label `sig1` repetido en Signature-Input: usa el primero; RFC 8941 dice que gana el último. | 8941 §4.2.2 |
| `P02` | aauth | Firma escrita en alfabeto base64url dentro de `:...:`: la acepta; RFC 8941 exige fallar. | 8941 §4.2.7 |

Rechazos espurios:

- **aauth**: no implementa `@query-param` ni `@request-target` (B.2.2, V11, V13); `@query` sin query da error en vez de `?` (V04); re-codifica `'` en la query (V14); no recorta OWS (V03) ni obs-fold (V20); usa Signature-Input textual en vez de re-serializarlo (V15); y re-chequea `Content-Digest` sólo con SHA-256, así que rechaza el `sha-512` del Apéndice B (B.2.3, V21). `tests/findings.rs` prueba que la base que arma para B.2.3 es la del RFC: el rechazo viene sólo del chequeo de digest.
- **wimsey**: no implementa `@query-param`, `@target-uri` ni `@scheme` (B.2.2, V10, V12, V13); no quita el puerto por defecto de `@authority` (V08; su documentación lo deja al integrador); usa Signature-Input textual (V15); no maneja obs-fold (V20).
- **web-bot-auth**: con un solo valor de campo no recorta OWS ni obs-fold (sólo lo hace con varias líneas) (V03, V20).

Casos ambiguos que dividen: `T23` (body cambiado con `Content-Digest` firmado: aauth lo rechaza al re-chequear el digest, los otros dos verifican sólo la firma, que es lo que define RFC 9421), `P03` (firmante que firma su propio texto no canónico: sólo web-bot-auth, que re-serializa, lo rechaza), `P04`/`P05` (dot segments), `P07` (componente en mayúsculas).

**Nota post-hoc (escrita después de correr):** `T10` se prerregistró como `reject`. Después de la corrida leí RFC 9110 §4.2.3, que permite a cualquier componente HTTP normalizar URIs; RFC 9421 §2.2.6 remite a esa sección pero sólo nombra la regla del path vacío y la comparación simple. Con esa lectura `T10` es discutible y quedaría como divergencia, no como aceptación indebida. El caso no se reclasificó en el código para no tocar el prerregistro; con la lectura estricta aauth tiene 6 aceptaciones indebidas, con la laxa 5. `T11` no cambia: `'` es un carácter reservado y RFC 9110 sólo hace equivalentes los no reservados.

### Criterios de aceptación (handoff)

| Criterio | Estado |
|---|---|
| ~30 casos + vectores del Apéndice B | **Cumplido**: 51 casos + 5 vectores |
| Contra web-bot-auth, wimsey-httpsig y aauth-httpsig | **Cumplido** (con la advertencia sobre la derivación de web-bot-auth) |
| Coincidencia de signature base | **Cumplido** por oráculo: con Ed25519 determinista, aceptar la firma de la referencia ⇔ base idéntica. Base textual directa sólo para aauth (B.2.3) |
| Contar aceptaciones indebidas | **Cumplido**: tabla arriba |
| Apéndice B pasa en todos | **No cumplido**: wimsey 4/5 (B.2.2) y aauth 3/5 (B.2.2, B.2.3). web-bot-auth 5/5 con la derivación de la referencia |

### Nivel de verificación

- **A**: compila, `clippy -D warnings` limpio, 9/9 tests (ninguno ignorado).
- **B**: la medición está hecha y es reproducible, con control positivo (la referencia reproduce las 5 bases del Apéndice B y coincide con los 50 veredictos decididos) y negativo (T20/T21).
- No B+/C: no hay línea base con la que competir ni uso bajo carga real.

### Límites

- Sólo requests, sólo Ed25519. Sin `sf`, `key`, `bs`, `tr`, `req`, respuestas ni B.2.4.
- Los vectores B.2.1–B.2.5 se verifican re-firmando la base del RFC con Ed25519, no con sus algoritmos originales.
- El modelo de request es uno solo para todos; cómo cada stack HTTP real entrega los headers (por ejemplo, si ya recorta OWS) puede cambiar V03/V20.
- Los crates no se fuzzearon; los hallazgos no se reportaron a sus mantenedores (lo decide Federico).
- Lectura de código fuente, no medida: en `web-bot-auth` 0.7.0, `Display` de `Algorithm::RsaV1_5Sha256` imprime `rsa-pss-sha512` (`src/keyring.rs`).

### Fuentes leídas

- RFC 9421: §2.1, §2.1.1, §2.1.2, §2.2.1–§2.2.8, §2.3, §2.5, §3.2, Apéndice B.1.4 y B.2 — <https://www.rfc-editor.org/rfc/rfc9421.txt>
- RFC 8941: §4.2.1.2, §4.2.2, §4.2.7 — <https://www.rfc-editor.org/rfc/rfc8941.txt>
- RFC 9110: §4.2.3 — <https://www.rfc-editor.org/rfc/rfc9110.txt>
- Metadatos de crates.io (API) y código fuente publicado de `web-bot-auth` 0.7.0, `wimsey-httpsig` 0.9.0 (y su README) y `aauth-httpsig` 0.1.2 (y su README).

---

## EN

**What:** 56 cases (5 RFC 9421 Appendix B.2 request vectors, 21 valid, 23 tampered, 7 parser edge cases), each with the RFC-expected verdict, run through `web-bot-auth` 0.7.0, `wimsey-httpsig` 0.9.0, `aauth-httpsig` 0.1.2 and a reference implementation written from the RFC. `web-bot-auth` delegates derived-component values to the integrator, so the adapter answers them with the reference derivation.

**Results** (`cargo run --release --bin httpsig-diff -- --csv results/matrix.csv --json results/summary.json`, deterministic):

| | reference | web-bot-auth | wimsey-httpsig | aauth-httpsig |
|---|---|---|---|---|
| Appendix B accepted (of 5) | 5 | 5 | 4 | 3 |
| Agree with RFC (of 50 decided) | 50 | 47 | 42 | 34 |
| Spurious rejections | 0 | 2 | 7 | 10 |
| Undue acceptances | 0 | 1 | 1 | 6 |

23/56 cases divergent across the three crates. Negative controls rejected by all.

**Notable:** aauth accepts a query whose `'` was percent-encoded after signing (T11, `url`-crate re-encoding), a path with added dot segments (T10, debatable under RFC 9110 §4.2.3, see the post-hoc note in the Spanish section), duplicate labels using the first (P01) and base64url signatures (P02); web-bot-auth and aauth ignore an `alg` parameter that contradicts the key (T16); wimsey and aauth accept a component covered twice (T18). aauth rejects Appendix B.2.3 only because its Content-Digest re-check knows SHA-256 alone.

**Acceptance criterion "Appendix B passes in all": not met** (wimsey 4/5, aauth 3/5).

**Verification level: B.** Limits: requests only, Ed25519 only, no structured-field component parameters, B.2.1–B.2.5 checked by re-signing the RFC base with Ed25519, findings not reported upstream.

## License

Apache-2.0
