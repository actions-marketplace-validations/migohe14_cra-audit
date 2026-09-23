# Notificar al INCIBE-CERT según el Reglamento de Ciberresiliencia (CRA)

Guía práctica para fabricantes de software con establecimiento principal en España, y cómo te ayuda
`cra-audit` en cada paso. Resume la información publicada por INCIBE-CERT el 09/09/2026
([fuente](https://www.incibe.es/incibe-cert/blog/reglamento-de-ciberresiliencia-cra-que-es-quien-afecta-y-como-prepararse))
y las [FAQ de ENISA sobre la plataforma de notificación](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions).
No es asesoramiento legal.

## Qué hay que notificar (art. 14 del CRA)

Desde el **11 de septiembre de 2026**, solo dos supuestos se notifican por la vía del CRA:

1. **Vulnerabilidades activamente explotadas** en un producto con elementos digitales.
2. **Incidentes graves** que tengan un impacto significativo en la seguridad de ese producto.

No hay que notificar cada CVE de tus dependencias: lo relevante es que la vulnerabilidad se esté explotando
**y afecte a tu producto**.

## A quién y por dónde

Por la **plataforma única de notificación (SRP) de ENISA**. Cada notificación llega a la vez a **INCIBE-CERT**,
el CSIRT coordinador en España, y a **ENISA**.

| Paso | Vulnerabilidad explotada | Incidente grave |
| --- | --- | --- |
| Alerta temprana | 24 h desde que tienes conocimiento | 24 h |
| Notificación | 72 h, con información general y evaluación inicial | 72 h |
| Informe final | 14 días desde que hay una medida correctora (p. ej. un parche) | 1 mes tras la notificación de 72 h |

## Pide el acceso a la SRP antes de necesitarlo

En España, el alta en la SRP **se coordina a través de INCIBE**:

1. Escribe a **cve-coordination@incibe.es** solicitando tu usuario para la plataforma SRP.
2. INCIBE te indica qué información y documentación necesita y **valida** que eres un sujeto obligado.
3. Superada la validación, te envía las instrucciones para completar el registro y empezar a notificar.

Como hay una validación previa, no esperes a tener un incidente: el plazo de 24 horas no se detiene.

## Si no es un caso del CRA

- **Otros incidentes de ciberseguridad** de tu organización: **incidencias@incibe-cert.es**.
- **Vulnerabilidades no conocidas (0-day)** que necesitan coordinación y un identificador CVE (INCIBE actúa como CNA):
  **cve-coordination@incibe.es**.
- **Si dudas** de si tu caso entra en el CRA, INCIBE recomienda notificarlo por sus canales habituales: si su equipo
  concluye que es un caso CRA, te indicará que lo registres formalmente en la SRP.

## Cómo te ayuda cra-audit

### 1. Enterarte a tiempo

```bash
npx cra-audit --country ES
```

Revisa todas tus dependencias (npm, Yarn, pnpm, Python, Go, Java o cualquier SBOM) contra OSV.dev y el catálogo
**CISA KEV** de vulnerabilidades explotadas. Si encuentra una, muestra los plazos del art. 14 y los pasos de
INCIBE-CERT para acceder a la SRP:

```text
⚠ CRA Art. 14 — actively exploited vulnerability in a dependency
  … notify INCIBE-CERT and ENISA through the Single Reporting Platform (SRP):
    • Early warning ........ within 24 hours of becoming aware
  INCIBE-CERT (ES) — access to the SRP:
    1. Email cve-coordination@incibe.es asking for a user on the ENISA Single Reporting Platform (SRP).
```

Guarda el país en la política para no repetirlo: `{ "country": "ES" }` en `.cra-audit.json`. En GitHub Actions:

```yaml
- uses: migohe14/cra-audit@v2
  with:
    country: ES
```

### 2. Decidir y documentar si te afecta

Que una dependencia esté en el KEV no significa que tu producto sea explotable. Registra tu valoración en
`.cra-audit.json` y genera el documento **VEX**, que es la prueba de la decisión que tomaste y cuándo:

```json
{
  "country": "ES",
  "vulnerabilities": {
    "allowlist": [
      { "id": "CVE-2020-11023", "package": "jquery", "status": "not_affected",
        "justification": "code_not_reachable",
        "detail": "No pasamos HTML no confiable a los métodos DOM de jQuery." }
    ]
  }
}
```

```bash
npx cra-audit vex -o vex.cdx.json
```

### 3. Tener tu política de seguridad en regla

```bash
npx cra-audit readiness --init --lang es --country ES
```

Crea un `SECURITY.md` en español (versiones con soporte, periodo de soporte, canal de comunicación, proceso de
divulgación coordinada y compromisos del art. 14 con la sección de INCIBE-CERT) y un `security.txt` (RFC 9116).
Rellena los `TODO` y vuelve a ejecutar `npx cra-audit readiness --country ES` para comprobarlo.

## Lista de preparación

- [ ] Cuenta de EU Login con autenticación en dos pasos para quien vaya a notificar.
- [ ] Acceso a la SRP solicitado a INCIBE (cve-coordination@incibe.es) y validado.
- [ ] `SECURITY.md` con contacto, periodo de soporte y procedimiento del art. 14 (`cra-audit readiness`).
- [ ] Vigilancia de vulnerabilidades explotadas en CI y de forma periódica (`cra-audit`, también con `schedule:` en GitHub Actions).
- [ ] Criterio documentado para decidir si una vulnerabilidad te afecta (VEX).
- [ ] Plantillas internas para la alerta temprana, la notificación de 72 h y el informe final.
- [ ] Canal para informar a los usuarios afectados (art. 14.8).
