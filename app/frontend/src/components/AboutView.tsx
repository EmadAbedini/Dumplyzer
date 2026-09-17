import {
  ABOUT_BODY,
  ABOUT_COMPONENTS_HEADING,
  ABOUT_COMPONENTS_INTRO,
  ABOUT_DEVELOPER,
  ABOUT_LINKS,
  ABOUT_TAGLINE,
} from "../lib/about";
import {
  CAPABILITY,
  CHECKING_DETAIL,
  technicalImplementationLine,
} from "../lib/analysisCapabilities";
import { openExternalUrl } from "../lib/api";
import { formatAppVersion } from "../lib/appMeta";
import { useCapabilityStatus } from "../lib/capabilityStatus";

type Props = {
  appName: string;
  appVersion: string;
};

function ComponentItem({
  capability,
  detail,
}: {
  capability: string;
  detail: string;
}) {
  return (
    <div className="min-w-0">
      <div className="text-sm font-medium tracking-tight">{capability}</div>
      <div className="mt-0.5 text-xs text-muted">{detail}</div>
    </div>
  );
}

export function AboutView({ appName, appVersion }: Props) {
  const version = formatAppVersion(appVersion);
  const caps = useCapabilityStatus();
  const yara = caps.yara;
  const peExtraction = caps.peExtraction;
  const capa = caps.capa;
  const floss = caps.floss;
  const bulkExtractor = caps.bulkExtractor;
  const engineVersion =
    caps.volatilityVersion || peExtraction?.volatility_version || null;

  const components = [
    {
      capability: CAPABILITY.memoryAnalysis,
      detail:
        caps.rows.memoryAnalysis.kind === "checking"
          ? CHECKING_DETAIL
          : technicalImplementationLine("Volatility 3", engineVersion, true),
    },
    {
      capability: CAPABILITY.artifactExtraction,
      detail:
        caps.rows.artifactExtraction.kind === "checking"
          ? CHECKING_DETAIL
          : technicalImplementationLine(
              "Bulk_Extractor",
              bulkExtractor?.bulk_extractor_version,
              Boolean(bulkExtractor?.available),
            ),
    },
    {
      capability: CAPABILITY.capabilityAnalysis,
      detail:
        caps.rows.capabilityAnalysis.kind === "checking"
          ? CHECKING_DETAIL
          : technicalImplementationLine(
              "CAPA",
              capa?.capa_version,
              Boolean(capa?.available),
            ),
    },
    {
      capability: CAPABILITY.stringAnalysis,
      detail:
        caps.rows.stringAnalysis.kind === "checking"
          ? CHECKING_DETAIL
          : technicalImplementationLine(
              "FLOSS",
              floss?.floss_version,
              Boolean(floss?.available),
            ),
    },
    {
      capability: CAPABILITY.signatureDetection,
      detail:
        caps.rows.signatureDetection.kind === "checking"
          ? CHECKING_DETAIL
          : technicalImplementationLine(
              "YARA",
              yara?.yara_version,
              Boolean(yara?.available),
            ),
    },
  ];

  return (
    <div className="mx-auto max-w-2xl p-5">
      <h2 className="text-base font-semibold tracking-tight">About</h2>
      <p className="mt-1 text-sm text-muted">
        {[appName, version].filter(Boolean).join(" ")}
      </p>

      <section className="card mt-5 p-4">
        <h3 className="text-lg font-semibold tracking-tight">
          {appName || "Dumplyzer"}
        </h3>
        <p className="mt-1 text-sm text-muted">{ABOUT_TAGLINE}</p>
        <div className="mt-3 space-y-2.5 text-sm leading-relaxed">
          {ABOUT_BODY.map((paragraph) => (
            <p key={paragraph}>{paragraph}</p>
          ))}
        </div>
        <div className="mt-5 border-t border-border pt-4">
          <div className="text-sm font-semibold">{ABOUT_DEVELOPER.heading}</div>
          <div className="mt-1 text-sm font-semibold">{ABOUT_DEVELOPER.name}</div>
          <div className="mt-0.5 text-sm text-muted">{ABOUT_DEVELOPER.role}</div>
          <div className="mt-3 flex items-center gap-2 text-sm">
            {ABOUT_LINKS.map((link, index) => (
              <span key={link.url} className="flex items-center gap-2">
                {index > 0 ? (
                  <span className="text-accent" aria-hidden="true">
                    ·
                  </span>
                ) : null}
                <a
                  href={link.url}
                  className="text-accent underline-offset-2 hover:underline"
                  onClick={(event) => {
                    event.preventDefault();
                    void openExternalUrl(link.url);
                  }}
                >
                  {link.label}
                </a>
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="card mt-4 p-4">
        <h3 className="text-sm font-semibold">{ABOUT_COMPONENTS_HEADING}</h3>
        <p className="mt-1 text-sm text-muted">{ABOUT_COMPONENTS_INTRO}</p>
        <div className="mt-4 grid grid-cols-1 gap-x-10 gap-y-4 sm:grid-cols-2">
          {components.map((item) => (
            <ComponentItem
              key={item.capability}
              capability={item.capability}
              detail={item.detail}
            />
          ))}
        </div>
      </section>
    </div>
  );
}
