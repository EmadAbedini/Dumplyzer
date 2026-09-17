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
