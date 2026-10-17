const defaultStackName = "artifact-server-cloudflare";

/** Use one validated state namespace for Alchemy and its deployment manifest. */
export function effectiveStackName(contentHostSuffix?: string): string {
  const name = process.env["ALCHEMY_STACK_NAME"] ?? defaultStackName;
  if (!/^[a-z0-9][a-z0-9-]{0,60}$/u.test(name)) {
    throw new Error("ALCHEMY_STACK_NAME must match /^[a-z0-9][a-z0-9-]{0,60}$/");
  }
  if (contentHostSuffix !== undefined && name === defaultStackName) {
    throw new Error("Group installations require a distinct ALCHEMY_STACK_NAME");
  }
  return name;
}

interface ContentHostRuntimeConfiguration {
  ARTIFACT_SERVER_CONTENT_HOST_SUFFIX?: string;
}

/** Compose optional group environment without mutating the upstream manifest. */
export function contentHostRuntimeConfiguration(suffix?: string): ContentHostRuntimeConfiguration {
  const configuration: ContentHostRuntimeConfiguration = {};
  if (suffix !== undefined) configuration.ARTIFACT_SERVER_CONTENT_HOST_SUFFIX = suffix;
  return configuration;
}
