# Taller 2MFA: TOTP desde cero + Step-Up Auth observable con Prefect

Prueba de concepto con dos piezas que **no se comunican entre sí** y aun así generan el mismo código:

| Carpeta | Qué es |
| --- | --- |
| [`mobile-authenticator/`](mobile-authenticator/) | App Authenticator en **React Native (Expo)**. SHA-1, HMAC, Base32 y truncamiento dinámico escritos a mano en [`src/totp.js`](mobile-authenticator/src/totp.js), sin librerías TOTP. Funciona en modo avión. |
| [`backend-prefect/`](backend-prefect/) | API **FastAPI** con Step-Up Auth, máquina de estados 2FA, Strategy (TOTP / respaldo), caché anti-replay y **flows de Prefect**. Incluye la **web app** de login en `/`. Usuarios en **Supabase** o, si no se configura, en **SQLite**. |

```text
Navegador ──POST /auth/login──▶ password-login-flow ──▶ pre_auth_token (scope=pre_auth)
                                                   │
App móvil (modo avión)                             ▼
HMAC-SHA1(secreto, unix//30) ──código──▶ POST /auth/verify-2fa ──▶ verify-2fa-flow
                                           ├─ validate_pre_auth_state
                                           ├─ check_anti_replay_cache   (ReplayAttackDetected)
                                           ├─ execute_mfa_strategy      (log: C-1 / C / C+1)
                                           └─ issue_elevated_session    ──▶ access_token (mfa_verified=true)
                                                                             │
                                                     GET /api/boveda-secreta ◀┘
```

## Requisitos

- Python 3.11+ y Node.js 20+
- Celular con **Expo Go** (misma red Wi-Fi que el PC solo para *cargar* la app; luego funciona offline) o un emulador Android.

## 1. Servidor de Prefect

```bash
cd backend-prefect
python3 -m venv .venv
source .venv/bin/activate          # fish: source .venv/bin/activate.fish
pip install -r requirements.txt
prefect server start               # UI en http://127.0.0.1:4200
```

## 2. Backend + web app (otra terminal)

```bash
cd backend-prefect
source .venv/bin/activate
cp .env.example .env               # edita JWT_SECRET; Supabase es opcional
uvicorn app.main:app --reload --port 8000
```

- Web app: <http://localhost:8000>
- Swagger: <http://localhost:8000/docs>
- `GET /health` indica qué base de datos se está usando (`supabase` o `sqlite`).

`.env` ya trae `PREFECT_API_URL=http://127.0.0.1:4200/api`, así que cada request crea un flow run visible en la UI.

### Supabase

El proyecto remoto es **Taller 2MFA** (`bnybkfxazlneagouwfqn`, us-east-1). El esquema está versionado como migración en [`backend-prefect/supabase/migrations/`](backend-prefect/supabase/migrations/) y la tabla `users` tiene RLS activado sin políticas, así que la key pública no puede leerla.

Para configurar el `.env` en otra máquina (con la Supabase CLI logueada):

```bash
cd backend-prefect
supabase link --project-ref bnybkfxazlneagouwfqn      # pide la contraseña de la base
supabase projects api-keys --project-ref bnybkfxazlneagouwfqn --reveal
# copia la key de tipo "secret" (sb_secret_...) en SUPABASE_SERVICE_KEY
```

- Esa key solo vive en el backend; nunca va en la app ni en la web.
- Sin `--reveal` la CLI devuelve la key enmascarada y el backend no arranca.
- Para aplicar cambios de esquema: `supabase db push`.
- `/health` debe responder `"database": "supabase"`. Si dejas `SUPABASE_URL` o `SUPABASE_SERVICE_KEY` vacíos, el backend usa SQLite local.

### Tests

```bash
cd backend-prefect && source .venv/bin/activate
pytest -q
```

Cubren los vectores oficiales de RFC 4226/6238, la detección de ventana, el Step-Up (un pre_auth_token no abre la bóveda), el replay, los códigos de respaldo de un solo uso y que ninguna contraseña llegue a Prefect. Usan SQLite temporal y un Prefect efímero, así que no dependen del `.env` ni tocan Supabase.

## 3. App móvil

```bash
cd mobile-authenticator
npm install
npx expo start
```

Escanea el QR de la terminal con Expo Go (Android) o con la cámara (iOS). Para emulador: tecla `a`.

Una vez abierta, la app no necesita red: el código se calcula localmente con el reloj del dispositivo.

- **Escanear QR**: lee la URI `otpauth://totp/...` que muestra la web app y extrae `secret`.
- **Pegar semilla**: para emuladores sin cámara, pega la semilla Base32 que la web app muestra bajo el QR.
- **Simular desfase de reloj (-30s / 0s / +30s)**: corre el reloj de la app para la prueba de clock skew.
- Mantén presionada una cuenta para eliminarla.

## Arquitectura y patrones

| Patrón | Dónde |
| --- | --- |
| **Máquina de estados** `DISABLED → PENDING_VERIFICATION → ACTIVE` | [`app/mfa_state.py`](backend-prefect/app/mfa_state.py). `POST /auth/2fa/setup` deja el estado en `PENDING_VERIFICATION`; solo el primer código válido (`POST /auth/2fa/activate`) lo pasa a `ACTIVE` y genera los códigos de respaldo. Si el usuario nunca escanea el QR, su login sigue funcionando y puede regenerarlo. |
| **Step-Up Authentication** | [`app/security.py`](backend-prefect/app/security.py). `POST /auth/login` entrega un JWT `scope=pre_auth` (5 min) que solo aceptan los endpoints de 2FA. `POST /auth/verify-2fa` entrega el JWT `scope=access` con `mfa_verified: true`, el único que acepta `GET /api/boveda-secreta`. |
| **Strategy** | [`app/strategies.py`](backend-prefect/app/strategies.py): `SecondFactorStrategy` → `TOTPStrategy` (ventanas C-1, C, C+1) y `BackupCodeStrategy` (8 códigos de 8 dígitos, guardados como SHA-256, un solo uso). Se elige con `"method": "totp" \| "backup"`. |
| **Anti-replay / idempotencia** | [`app/replay_cache.py`](backend-prefect/app/replay_cache.py): diccionario en memoria `(user_id, código) → timestamp` con TTL de 90 s. `check_anti_replay_cache` lo consulta y `issue_elevated_session` lo marca con check-and-set atómico, así que dos peticiones simultáneas con el mismo código tampoco pasan. |
| **Orquestación con Prefect** | [`app/flows.py`](backend-prefect/app/flows.py): `password-login-flow`, `mfa-provisioning-flow`, `mfa-activation-flow` y `verify-2fa-flow`, con las 4 tasks pedidas. Todas usan `cache_policy=NO_CACHE`, para que una validación nunca se resuelva desde caché. |

### Endpoints

| Método | Ruta | Token | Descripción |
| --- | --- | --- | --- |
| POST | `/auth/register` | — | Crea usuario |
| POST | `/auth/login` | — | Devuelve `pre_auth_token` + `mfa_state` |
| POST | `/auth/2fa/setup` | pre_auth | Genera secreto + QR → `PENDING_VERIFICATION` |
| POST | `/auth/2fa/activate` | pre_auth | Primer código → `ACTIVE`, códigos de respaldo y access_token |
| POST | `/auth/verify-2fa` | pre_auth | Código TOTP o de respaldo → `access_token` |
| GET | `/api/boveda-secreta` | access (`mfa_verified`) | Recurso protegido |


> Nota: la caché anti-replay vive en memoria, así que se reinicia con `--reload`. Es lo que pide el alcance del laboratorio; en producción iría en Redis.

### Decisiones de seguridad

- **Secretos fuera de Prefect.** La contraseña y el `pre_auth_token` llegan a los flows como `SecretStr`, así que en la UI de Prefect aparecen como `**********`. El código de 6 dígitos sí se ve, porque es de un solo uso y permite ver en la demo qué código se intentó repetir.
- **Lo que se guarda en la base.** Las contraseñas se guardan con PBKDF2-SHA256 (200k iteraciones) y los códigos de respaldo como SHA-256. La semilla TOTP queda en claro, porque el servidor la necesita para calcular el HMAC.
- **Fuera del alcance del laboratorio:**
  - No hay límite de intentos fallidos por `pre_auth_token`.
  - El `pre_auth_token` se puede reusar durante sus 5 minutos de vida. Un replay con un login nuevo falla justo en `check_anti_replay_cache`, que es lo que pide la rúbrica.

## Verificación

```bash
cd backend-prefect && pytest -q                   # 9 tests (RFC, step-up, replay, respaldo, secretos en Prefect)
cd mobile-authenticator && npm run lint && npx expo-doctor
```
