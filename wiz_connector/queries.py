"""Wiz GraphQL query definitions.

Sourced directly from Wiz API documentation:
  https://docs.wiz.io/docs/wiz-api-for-pulling-issues
  https://docs.wiz.io/docs/get-ccf
  https://docs.wiz.io/docs/get-vulnerabilities
  https://docs.wiz.io/docs/get-vm-hostname
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 1. Issues — security findings raised by Wiz controls / event rules
# ---------------------------------------------------------------------------

ISSUES_QUERY = """
query IssuesPage(
  $filterBy: IssueFilters
  $first: Int
  $after: String
  $orderBy: IssueOrder
) {
  issues(
    filterBy: $filterBy
    first: $first
    after: $after
    orderBy: $orderBy
  ) {
    totalCount
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      id
      status
      severity
      type
      createdAt
      updatedAt
      dueAt
      resolvedAt
      statusChangedAt
      note
      sourceRule {
        __typename
        ... on Control {
          id
          name
          description
          severity
          remediationInstructions
          securitySubCategories {
            title
            category {
              name
              framework { name }
            }
          }
        }
        ... on CloudEventRule {
          id
          name
          description
          severity
          sourceType
        }
      }
      entity {
        id
        name
        type
      }
      entitySnapshot {
        id
        type
        name
        status
        cloudPlatform
        cloudProviderURL
        providerId
        region
        resourceGroupExternalId
        subscriptionExternalId
        subscriptionName
        subscriptionTags
        nativeType
        tags
      }
      projects {
        id
        name
        slug
        businessUnit
        riskProfile { businessImpact }
      }
      serviceTickets {
        externalId
        name
        url
      }
    }
  }
}
"""

# ---------------------------------------------------------------------------
# 2. Cloud Configuration Findings (CCF) — misconfigurations
#    Uses analyzedAt delta filter for incremental pulls.
# ---------------------------------------------------------------------------

CCF_QUERY = """
query CloudConfigurationFindingsPage(
  $filterBy: ConfigurationFindingFilters
  $orderBy: ConfigurationFindingOrder
  $first: Int
  $after: String
) {
  configurationFindings(
    filterBy: $filterBy
    orderBy: $orderBy
    first: $first
    after: $after
  ) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      id
      name
      analyzedAt
      firstSeenAt
      severity
      result
      status
      remediation
      source
      targetExternalId
      ignoreRules {
        id
        tags { key value }
      }
      subscription {
        id
        name
        externalId
        cloudProvider
      }
      resource {
        id
        name
        type
        status
        projects {
          id
          name
          riskProfile { businessImpact }
        }
      }
      rule {
        id
        shortId
        graphId
        name
        description
        remediationInstructions
        securitySubCategories {
          id
          title
          category { id }
        }
        tags { key value }
      }
    }
  }
}
"""

# ---------------------------------------------------------------------------
# 3. Vulnerabilities — CVE findings across all asset types
#    Uses updatedAt delta filter for incremental pulls.
# ---------------------------------------------------------------------------

VULNERABILITIES_QUERY = """
query VulnerabilityFindingsPage(
  $filterBy: VulnerabilityFindingFilters
  $first: Int
  $after: String
  $orderBy: VulnerabilityFindingOrder
) {
  vulnerabilityFindings(
    filterBy: $filterBy
    first: $first
    after: $after
    orderBy: $orderBy
  ) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      id
      name
      detailedName
      isHighProfileThreat
      description
      severity
      vendorSeverity
      nvdSeverity
      weightedSeverity
      status
      fixedVersion
      detectionMethod
      hasExploit
      hasCisaKevExploit
      cisaKevDueDate
      firstDetectedAt
      lastDetectedAt
      resolvedAt
      score
      validatedInRuntime
      epssSeverity
      epssPercentile
      epssProbability
      hasInitialAccessPotential
      publishedDate
      categories
      projects {
        id
        name
        slug
      }
      vulnerableAsset {
        ... on VulnerableAssetBase {
          id
          type
          name
          cloudPlatform
          subscriptionName
          subscriptionExternalId
          subscriptionId
          tags
          hasLimitedInternetExposure
          hasWideInternetExposure
          nativeType
        }
        ... on VulnerableAssetVirtualMachine {
          id
          type
          name
          cloudPlatform
          subscriptionName
          subscriptionExternalId
          subscriptionId
          tags
          operatingSystem
          imageName
          hasLimitedInternetExposure
          hasWideInternetExposure
          isAccessibleFromVPN
          nativeType
        }
        ... on VulnerableAssetServerless {
          id
          type
          name
          cloudPlatform
          subscriptionId
          tags
          hasLimitedInternetExposure
          hasWideInternetExposure
          nativeType
        }
        ... on VulnerableAssetContainerImage {
          id
          type
          name
          cloudPlatform
          subscriptionId
          tags
          hasWideInternetExposure
          nativeType
        }
        ... on VulnerableAssetContainer {
          id
          type
          name
          cloudPlatform
          subscriptionId
          tags
          nativeType
        }
        ... on VulnerableAssetCommon {
          id
          type
          name
          cloudPlatform
          subscriptionId
          tags
          nativeType
        }
      }
    }
  }
}
"""

# ---------------------------------------------------------------------------
# 4. Cloud resources (graphSearch) — asset inventory / attack surface
#    projectId="*" queries across all projects.
#    properties JSON blob contains hostname, IPs, OS, and cloud metadata.
# ---------------------------------------------------------------------------

CLOUD_RESOURCES_QUERY = """
query GraphSearch(
  $query: GraphEntityQueryInput
  $projectId: String!
  $first: Int
  $after: String
  $quick: Boolean = true
) {
  graphSearch(
    query: $query
    projectId: $projectId
    first: $first
    after: $after
    quick: $quick
  ) {
    pageInfo {
      endCursor
      hasNextPage
    }
    nodes {
      entities {
        id
        name
        type
        properties
      }
    }
  }
}
"""

# ---------------------------------------------------------------------------
# Default filter / variable values
# ---------------------------------------------------------------------------

DEFAULT_ISSUE_FILTERS: dict[str, object] = {
    "status": ["OPEN", "IN_PROGRESS"],
    "severity": ["CRITICAL", "HIGH", "MEDIUM"],
}

DEFAULT_ISSUE_ORDER: dict[str, str] = {
    "field": "SEVERITY",
    "direction": "DESC",
}

# CCF: analyzedAt.inLast populated dynamically; static defaults below
DEFAULT_CCF_FILTERS: dict[str, object] = {
    "severity": ["CRITICAL", "HIGH", "MEDIUM"],
    "status": ["OPEN"],
    "resource": {},           # nested resource sub-filters (cloudPlatform etc.)
}

DEFAULT_CCF_ORDER: dict[str, str] = {
    "field": "SEVERITY",
    "direction": "DESC",
}

# Vulnerabilities: updatedAt.inLast populated dynamically
DEFAULT_VULN_FILTERS: dict[str, object] = {
    "severity": ["CRITICAL", "HIGH", "MEDIUM"],
    "status": ["OPEN"],
    "assetStatus": ["Active"],
}

DEFAULT_VULN_ORDER: dict[str, str] = {
    "field": "CREATED_AT",
    "direction": "DESC",
}

# graphSearch: all projects, specific asset types, accurate (not quick) mode
CLOUD_RESOURCES_VARIABLES: dict[str, object] = {
    "quick": False,
    "projectId": "*",
    "query": {
        "type": [
            "VIRTUAL_MACHINE",
            "CONTAINER",
            "SERVERLESS",
            "DATABASE",
            "STORAGE_BUCKET",
            "LOAD_BALANCER",
            "NETWORK_INTERFACE",
            "KUBERNETES_NODE",
            "CLOUD_ACCOUNT",
        ],
        "select": True,
    },
}

# Payload type discriminator written into each Kafka message so the
# WizNormaliser can route each record to the correct scoring path.
PAYLOAD_TYPE_ISSUE = "issue"
PAYLOAD_TYPE_CCF = "ccf"
PAYLOAD_TYPE_VULNERABILITY = "vulnerability"
