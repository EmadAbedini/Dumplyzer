export const ABOUT_TAGLINE = "Advanced Memory Forensics Platform";

export const ABOUT_BODY: readonly string[] = [
  "Dumplyzer is an open-source, offline desktop workbench designed to make memory forensics faster, simpler, and more accessible for DFIR professionals, threat hunters, malware analysts, and anyone working with memory images.",
  "It brings essential memory-analysis workflows into a single focused workspace, covering memory-image analysis, process investigation, memory regions, network activity, artifacts, indicators, and forensic findings.",
  "Analysis is performed locally on the analyst's workstation. Evidence remains in its original location and is never copied into the application installation directory.",
];

export const ABOUT_DEVELOPER = {
  heading: "Developed by",
  name: "Emad Abedini",
  role: "Detection Engineer | Malware Researcher | DFIR",
} as const;

export const ABOUT_LINKS = [
  { label: "GitHub", url: "https://github.com/EmadAbedini/Dumplyzer" },
  { label: "LinkedIn", url: "https://www.linkedin.com/in/emad-abedini" },
] as const;

export const ABOUT_COMPONENTS_HEADING = "Analysis Components";

export const ABOUT_COMPONENTS_INTRO =
  "Dumplyzer integrates established open-source analysis engines and tools.";

/** Product license as shown in About. SPDX id matches package.json / LICENSE. */
export const ABOUT_LICENSE = {
  heading: "License",
  copyright: `© 2026 ${ABOUT_DEVELOPER.name}`,
  summary:
    "Dumplyzer application source is licensed under the Apache License, Version 2.0.",
  thirdParty:
    "Bundled analysis engines and tools remain under their original licenses. Dumplyzer does not relicense them.",
  links: [
    {
      label: "Apache License 2.0",
      url: "https://www.apache.org/licenses/LICENSE-2.0",
    },
    {
      label: "Third-Party Notices",
      url: "https://github.com/EmadAbedini/Dumplyzer/blob/main/THIRD_PARTY_NOTICES.md",
    },
  ],
} as const;
