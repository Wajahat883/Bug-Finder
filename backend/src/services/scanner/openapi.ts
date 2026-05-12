import { ScanContext, DiscoveredParam, ctxFetch } from "./types";

interface OpenApiParameter {
  name: string;
  in: "query" | "body" | "path" | "header" | "formData" | "cookie";
  required?: boolean;
}

interface OpenApiPathItem {
  parameters?: OpenApiParameter[];
  get?: { parameters?: OpenApiParameter[] };
  post?: { parameters?: OpenApiParameter[] };
  put?: { parameters?: OpenApiParameter[] };
  patch?: { parameters?: OpenApiParameter[] };
  delete?: { parameters?: OpenApiParameter[] };
}

interface OpenApiV3Schema {
  openapi?: string;
  swagger?: string;
  paths?: Record<string, OpenApiPathItem>;
  components?: { schemas?: Record<string, unknown> };
}

const SPEC_PATHS = [
  "/swagger.json", "/openapi.json", "/swagger/v1/swagger.json",
  "/api/swagger.json", "/api/openapi.json", "/api/v1/swagger.json",
  "/api/v2/swagger.json", "/docs/swagger.json", "/api-docs",
  "/api-docs.json", "/v1/api-docs", "/v2/api-docs",
];

function extractParams(op: { parameters?: OpenApiParameter[] } | undefined, pathParams: OpenApiParameter[]): OpenApiParameter[] {
  return [...(pathParams ?? []), ...(op?.parameters ?? [])];
}

export async function runOpenApiDiscovery(ctx: ScanContext): Promise<void> {
  const { targetUrl, emit, discoveredEndpoints, discoveredParams } = ctx;
  const base = new URL(targetUrl).origin;

  emit({ type: "engine_start", engine: "Bug-Finder/OpenAPI", message: "Probing for OpenAPI/Swagger spec to discover real parameters" });

  let spec: OpenApiV3Schema | null = null;
  let specUrl = "";

  for (const path of SPEC_PATHS) {
    const res = await ctxFetch(ctx, `${base}${path}`, { headers: { Accept: "application/json" } }, 6000);
    if (!res || res.status !== 200) continue;
    const ct = res.headers.get("content-type") ?? "";
    if (!ct.includes("json") && !ct.includes("yaml")) continue;
    try {
      const text = await res.text();
      const parsed = JSON.parse(text) as OpenApiV3Schema;
      if (parsed.paths && typeof parsed.paths === "object") {
        spec = parsed;
        specUrl = `${base}${path}`;
        break;
      }
    } catch { /* not JSON or not a spec */ }
  }

  if (!spec || !spec.paths) {
    emit({ type: "log", message: "No OpenAPI/Swagger spec found — using heuristic parameter lists" });
    emit({ type: "engine_done", engine: "Bug-Finder/OpenAPI", message: "OpenAPI discovery skipped (no spec)" });
    return;
  }

  emit({ type: "log", message: `OpenAPI spec found at ${specUrl}` });

  let endpointsAdded = 0;
  let paramsAdded = 0;

  for (const [pathTemplate, pathItem] of Object.entries(spec.paths)) {
    const pathLevelParams = pathItem.parameters ?? [];
    const methods = ["get", "post", "put", "patch", "delete"] as const;

    for (const method of methods) {
      const op = pathItem[method];
      if (!op) continue;

      // Resolve path template to concrete URL — replace {id} style params with "1"
      const concretePath = pathTemplate.replace(/\{[^}]+\}/g, "1");
      const fullUrl = `${base}${concretePath}`;

      if (!discoveredEndpoints.includes(fullUrl)) {
        discoveredEndpoints.push(fullUrl);
        endpointsAdded++;
      }

      const allParams = extractParams(op, pathLevelParams);
      for (const param of allParams) {
        if (!param.name || !param.in) continue;
        const loc = param.in === "formData" ? "body" : param.in === "cookie" ? "header" : param.in;
        const dp: DiscoveredParam = {
          endpoint: `${method.toUpperCase()} ${fullUrl}`,
          name: param.name,
          location: loc as DiscoveredParam["location"],
        };
        if (!discoveredParams.some(p => p.endpoint === dp.endpoint && p.name === dp.name)) {
          discoveredParams.push(dp);
          paramsAdded++;
        }
      }

      // OpenAPI v3: request body schema fields → body params
      const opAny = op as Record<string, unknown>;
      if (opAny["requestBody"]) {
        const rb = opAny["requestBody"] as Record<string, unknown>;
        const content = rb["content"] as Record<string, unknown> | undefined;
        if (content) {
          for (const mediaType of Object.values(content)) {
            const mt = mediaType as Record<string, unknown>;
            const schemaProps = ((mt["schema"] as Record<string, unknown>)?.["properties"]) as Record<string, unknown> | undefined;
            if (schemaProps) {
              for (const fieldName of Object.keys(schemaProps)) {
                const dp: DiscoveredParam = {
                  endpoint: `${method.toUpperCase()} ${fullUrl}`,
                  name: fieldName,
                  location: "body",
                };
                if (!discoveredParams.some(p => p.endpoint === dp.endpoint && p.name === dp.name)) {
                  discoveredParams.push(dp);
                  paramsAdded++;
                }
              }
            }
          }
        }
      }
    }
  }

  emit({ type: "log", message: `OpenAPI: ${endpointsAdded} endpoints added, ${paramsAdded} parameters discovered` });
  emit({ type: "engine_done", engine: "Bug-Finder/OpenAPI", message: `OpenAPI discovery complete — ${paramsAdded} params from ${specUrl}` });
}
