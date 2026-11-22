import { resolveAgentWorkspaceDir } from "../agents/agent-scope.js";
import type { ParticipationCeiling } from "../agents/participation-ceiling.js";
import { sessionCreatorProfileId } from "../config/sessions/session-entry-provenance.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import type { PluginGatewayAccessAuthority } from "../plugins/gateway-access-policy.types.js";
import { roleScopesAllow } from "../shared/operator-scope-compat.js";
import { PARTICIPATION_TOOL_ALLOWLIST } from "../shared/participation-tools.js";
import {
  immutableGitHubPublicationParticipation,
  type GitHubPublicationParticipation,
  type GitHubPublicationRequesterSnapshot,
} from "../state/github-publication-requester.js";
import { UserProfileMutationUnsettledError } from "../state/user-profile-events.js";
import type { prepareUserProfileIdentity } from "../state/user-profile-list.js";
import type { UserProfileAccessFacts } from "../state/user-profiles.types.js";
import { resolveUserPath } from "../utils.js";
import { GitHubPublicationRequesterUnavailableError } from "./github-publication-failure.js";
import { GitHubPublicationRecoveryPendingError } from "./github-publication-git-index.js";
import {
  isOpenClawIdTunnelPrincipalCurrent,
  openclawIdSubjectRolePolicy,
} from "./openclaw-id/tunnel-principal.js";
import {
  GatewayOperatorAccessDeniedError,
  resumeGatewayOperatorAccessGrant,
} from "./operator-access-policy.js";
import { operatorRoleSubject } from "./operator-role-enforcement.js";
import { resolveOperatorRolePolicyForAssignment } from "./operator-role-policy.js";
import { createSyntheticPluginRuntimeClient } from "./server-plugin-runtime-client.js";
import { prepareSessionCreatorProfile } from "./session-creator.js";
import { resolveSessionMemberAccess } from "./session-member-access.js";
import {
  authorizePreparedSessionMutation,
  authorizeSessionAgentRun,
  resolveSessionVisibility,
} from "./session-sharing-policy.js";
import type { prepareSessionMutationFacts } from "./session-sharing-preparation.js";
import type { ExistingSessionMutationFacts } from "./session-sharing-target.types.js";

type PublicationSession = { sessionKey: string; agentId: string };
type PreparedProfileIdentity = Awaited<ReturnType<typeof prepareUserProfileIdentity>>;
type PreparedPublicationSession = Awaited<ReturnType<typeof prepareSessionMutationFacts>>;

export function publicationParticipationTarget(facts: ExistingSessionMutationFacts) {
  return Object.freeze({
    agentId: facts.target.agentId,
    sessionKey: facts.target.canonicalKey,
    sessionId: facts.target.entry.sessionId,
    lifecycleRevision: facts.target.entry.lifecycleRevision ?? null,
  });
}

function publicationParticipationSource(
  facts: ExistingSessionMutationFacts,
  config: OpenClawConfig,
) {
  return {
    agentId: facts.target.agentId,
    sessionId: facts.target.entry.sessionId,
    lifecycleRevision: facts.target.entry.lifecycleRevision ?? null,
    creatorProfileId: sessionCreatorProfileId(facts.target.entry.createdActor),
    root: resolveUserPath(
      facts.target.entry.sessionRoot ??
        facts.target.entry.spawnedWorkspaceDir ??
        resolveAgentWorkspaceDir(config, facts.target.agentId),
    ),
  };
}

/** The original invitation is distinct from the exact session selected for publication. */
export function capturePublicationParticipation(
  ceiling: ParticipationCeiling,
  facts: ExistingSessionMutationFacts,
  config: OpenClawConfig,
): GitHubPublicationParticipation {
  const source = ceiling.source ?? publicationParticipationSource(facts, config);
  if (
    !source.creatorProfileId ||
    (!ceiling.source && ceiling.sessionKey !== facts.target.canonicalKey)
  ) {
    throw new GitHubPublicationRequesterUnavailableError();
  }
  return immutableGitHubPublicationParticipation({
    ceiling: { ...ceiling, source: { ...source, creatorProfileId: source.creatorProfileId } },
    target: publicationParticipationTarget(facts),
  });
}

function readPublicationFacts(
  prepared: PreparedPublicationSession | undefined,
  config: OpenClawConfig,
) {
  try {
    if (!prepared) {
      throw new Error("Prepared publication session is missing");
    }
    return prepared.readCurrent(config);
  } catch (error) {
    throw new GitHubPublicationRecoveryPendingError(
      "GitHub publication session authorization is unavailable; retry after session storage is ready.",
      { cause: error },
    );
  }
}

export function prepareRequesterPolicy(
  snapshot: GitHubPublicationRequesterSnapshot,
  session: PublicationSession,
  getCommittedRuntimeConfig: () => OpenClawConfig,
  identity: PreparedProfileIdentity | undefined,
  sessionFacts: PreparedPublicationSession | undefined,
  onPolicy?: (authority: PluginGatewayAccessAuthority | undefined) => void,
  originFacts?: PreparedPublicationSession,
  participationFacts?: PreparedPublicationSession,
) {
  const client = createSyntheticPluginRuntimeClient({
    operatorRoleActor: snapshot.actor,
    openclawIdPrincipal: snapshot.openclawIdPrincipal,
    scopes: [...snapshot.scopes],
  });
  let retainedAuthority: PluginGatewayAccessAuthority | undefined;
  const assertIdentity = () => {
    if (snapshot.actor.kind !== "operator") {
      return undefined;
    }
    try {
      if (!identity) {
        throw new GitHubPublicationRequesterUnavailableError();
      }
      return identity.readCurrentFacts(snapshot.grant?.aliasBindingIds);
    } catch (error) {
      if (error instanceof UserProfileMutationUnsettledError) {
        throw new GitHubPublicationRecoveryPendingError(
          "GitHub publication identity authorization is unavailable; retry after the profile mutation settles.",
          { cause: error },
        );
      }
      throw new GitHubPublicationRequesterUnavailableError();
    }
  };
  const assertRole = (profile: UserProfileAccessFacts | undefined, config: OpenClawConfig) => {
    // Records with neither a principal nor a source cannot distinguish member and
    // other sign-ins. Linked profiles must request those publications again.
    if (
      !snapshot.authenticationSource &&
      !snapshot.openclawIdPrincipal &&
      profile?.hasOpenClawIdIdentity
    ) {
      throw new GitHubPublicationRequesterUnavailableError();
    }
    const principal = snapshot.openclawIdPrincipal;
    if (principal && !isOpenClawIdTunnelPrincipalCurrent(principal)) {
      throw new GitHubPublicationRequesterUnavailableError();
    }
    const role = openclawIdSubjectRolePolicy(principal, () =>
      profile
        ? resolveOperatorRolePolicyForAssignment(
            profile.profileId,
            profile.assignedRole,
            config,
            profile.githubLogin ?? null,
            operatorRoleSubject(profile),
          )
        : undefined,
    );
    if (
      !roleScopesAllow({
        role: "operator",
        requestedScopes: [
          snapshot.participation ? "operator.sessions.read" : "operator.sessions.write",
        ],
        allowedScopes: snapshot.scopes,
      }) ||
      (role &&
        (!roleScopesAllow({
          role: "operator",
          requestedScopes: snapshot.scopes,
          allowedScopes: role.scopes,
        }) ||
          (role.accessPolicyPlugin && role.accessPolicyPlugin !== snapshot.grant?.pluginId)))
    ) {
      throw new GitHubPublicationRequesterUnavailableError();
    }
    return role;
  };
  const assertPrepared = (config: OpenClawConfig) => {
    const current = assertIdentity();
    const role = assertRole(current?.profile, config);
    const participation = snapshot.participation;
    if (participation) {
      const { ceiling, target } = participation;
      const facts = readPublicationFacts(participationFacts, config);
      const source = publicationParticipationSource(facts, config);
      const access = resolveSessionMemberAccess({
        policy: role,
        scopes: snapshot.scopes,
        creator: false,
        admin: false,
        member: {
          present: facts.membership.has(ceiling.profileId),
          access: facts.memberAccess?.[ceiling.profileId],
        },
        visibility: resolveSessionVisibility(facts.target.entry),
        incognito: facts.target.entry.incognito,
      });
      if (
        !current ||
        snapshot.actor.kind !== "operator" ||
        snapshot.actor.profileId !== ceiling.profileId ||
        target.agentId !== session.agentId ||
        target.sessionKey !== session.sessionKey ||
        facts.target.canonicalKey !== ceiling.sessionKey ||
        source.agentId !== session.agentId ||
        source.agentId !== ceiling.source.agentId ||
        source.sessionId !== ceiling.source.sessionId ||
        source.lifecycleRevision !== ceiling.source.lifecycleRevision ||
        source.creatorProfileId !== ceiling.source.creatorProfileId ||
        source.root !== ceiling.source.root ||
        facts.target.entry.archivedAt !== undefined ||
        access.access !== "send" ||
        access.invitedAccessCeiling !== "send" ||
        !ceiling.tools?.includes("github_publish") ||
        !(role?.sessions.invitedTools ?? PARTICIPATION_TOOL_ALLOWLIST).includes("github_publish") ||
        authorizeSessionAgentRun(
          { cfg: config, client, target: facts.target, invitedSession: true },
          { policy: role },
        )
      ) {
        throw new GitHubPublicationRequesterUnavailableError();
      }
    }
    const targets = [
      { session, prepared: sessionFacts, origin: undefined },
      ...(snapshot.origin
        ? [{ session: snapshot.origin, prepared: originFacts, origin: snapshot.origin }]
        : []),
    ];
    for (const target of targets) {
      if (!current && !target.origin) {
        continue;
      }
      const facts = readPublicationFacts(target.prepared, config);
      if (
        participation &&
        !target.origin &&
        (facts.target.agentId !== participation.target.agentId ||
          facts.target.canonicalKey !== participation.target.sessionKey ||
          facts.target.entry.sessionId !== participation.target.sessionId ||
          (facts.target.entry.lifecycleRevision ?? null) !==
            participation.target.lifecycleRevision ||
          facts.target.entry.archivedAt !== undefined)
      ) {
        throw new GitHubPublicationRequesterUnavailableError();
      }
      if (
        target.origin &&
        (facts.target.entry.sessionId !== target.origin.sessionId ||
          (facts.target.entry.lifecycleRevision ?? null) !== target.origin.lifecycleRevision)
      ) {
        throw new GitHubPublicationRequesterUnavailableError();
      }
      if (!current || participation) {
        continue;
      }
      // Publication's creator restriction must preserve independently admitted capabilities.
      if (
        snapshot.actor.kind === "operator" &&
        !roleScopesAllow({
          role: "operator",
          requestedScopes: ["operator.write"],
          allowedScopes: snapshot.scopes,
        }) &&
        !prepareSessionCreatorProfile(
          snapshot.actor.profileId,
          current.aliases,
        )(facts.target.entry.createdActor)
      ) {
        throw new GitHubPublicationRequesterUnavailableError();
      }
      if (
        authorizePreparedSessionMutation({ cfg: config, client, ...target.session }, facts, {
          policy: role,
          aliases: current.aliases,
          // Publication mutates a session without starting an agent run.
          authorizesAgentRun: false,
        })
      ) {
        throw new GitHubPublicationRequesterUnavailableError();
      }
    }
    return current?.profile;
  };
  return () => {
    const config = getCommittedRuntimeConfig();
    const profile = assertPrepared(config);
    if (profile) {
      try {
        const authority = resumeGatewayOperatorAccessGrant(profile, config, snapshot.grant, {
          retained: retainedAuthority,
          openclawIdPrincipal: snapshot.openclawIdPrincipal,
        });
        retainedAuthority = authority;
        onPolicy?.(authority);
      } catch (error) {
        if (error instanceof GatewayOperatorAccessDeniedError) {
          throw new GitHubPublicationRequesterUnavailableError();
        }
        throw error;
      }
      // A policy callback can synchronously change identity, role, or committed config.
      assertPrepared(getCommittedRuntimeConfig());
    }
  };
}
