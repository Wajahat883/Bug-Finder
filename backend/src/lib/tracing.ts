// POINT 12: OpenTelemetry traces + POINT 9: Correlation IDs
import { NodeSDK } from "@opentelemetry/sdk-node";
import { getNodeAutoInstrumentations } from "@opentelemetry/auto-instrumentations-node";
import { PrometheusExporter } from "@opentelemetry/exporter-prometheus";
import { logger } from "./logger";

let sdk: NodeSDK | null = null;

export function initTracing(): void {
  try {
    const prometheusExporter = new PrometheusExporter({ port: 9464 }, () => {
      logger.info("Prometheus metrics available at http://localhost:9464/metrics");
    });

    sdk = new NodeSDK({
      metricReader: prometheusExporter,
      instrumentations: [
        getNodeAutoInstrumentations({
          "@opentelemetry/instrumentation-fs": { enabled: false },
          "@opentelemetry/instrumentation-http": { enabled: true },
          "@opentelemetry/instrumentation-express": { enabled: true },
        }),
      ],
    });

    sdk.start();
    logger.info("OpenTelemetry SDK started — traces and metrics active");
  } catch (err) {
    logger.warn({ err }, "OpenTelemetry init failed — continuing without tracing");
  }
}

export async function shutdownTracing(): Promise<void> {
  if (sdk) {
    try { await sdk.shutdown(); } catch { /* ignore */ }
  }
}
