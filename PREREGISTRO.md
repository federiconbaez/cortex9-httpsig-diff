# Prerregistro / Pre-registration

Escrito y commiteado antes de la primera corrida de la matriz contra los
crates. Written and committed before the first run of the matrix against the
crates.

Comando / command:

```sh
cargo run --release --bin httpsig-diff -- --csv results/matrix.csv --json results/summary.json
```

## Implementaciones / implementations

| Crate | Versión | Entrada usada |
|---|---|---|
| `web-bot-auth` | 0.7.0 | `MessageVerifier::parse` + `verify` con la clave pasada por id |
| `wimsey-httpsig` | 0.9.0 | `verify` con `VerifyConfig { label }`, perfil WIMSE apagado |
| `aauth-httpsig` | 0.1.2 | `prepare_verification` + `UnverifiedSignature::verify` |
| `reference` (este repo) | — | escrita desde el texto de RFC 9421; control positivo |

`web-bot-auth` no deriva los componentes `@...`: se los pide al integrador.
El adaptador le responde con la derivación de la referencia, así que para
`web-bot-auth` lo que se prueba es la parte propia del crate (parseo de los
campos, elección del label, combinación de líneas, serialización de
`@signature-params` y verificación).

## Corpus

5 vectores del Apéndice B.2 (B.2.1, B.2.2, B.2.3, B.2.5 re-firmados con
`test-key-ed25519` sobre la base impresa en el RFC; B.2.6 con su firma
original) + 21 casos válidos (`V*`) + 23 alterados (`T*`) + 7 de parseo (`P*`).
Cada caso tiene el veredicto que espera el RFC (`accept`, `reject` o
`ambiguous` cuando el texto leído no lo decide) y la sección que lo decide.

## Métricas

| Id | Métrica | Definición |
|---|---|---|
| D1 | Divergencias | casos donde los 3 crates no dan el mismo veredicto |
| D2 | Rechazos espurios por crate | casos `accept` que el crate rechaza |
| D3 | Aceptaciones indebidas por crate | casos `reject` que el crate acepta |
| D4 | Apéndice B por crate | vectores B.2 aceptados, de 5 |

## Controles

- Positivo: la referencia reconstruye byte a byte las 5 bases del Apéndice B y
  coincide con el veredicto esperado en todos los casos decididos.
- Negativo: `T20` (firma alterada) y `T21` (otra clave) tienen que ser
  rechazados por todas las implementaciones.

## Criterio de aceptación del build (handoff)

"Apéndice B pasa en todos": se reporta D4 tal cual. Si algún crate no pasa
algún vector, el criterio queda **no cumplido** para ese crate y se dice por
qué.
