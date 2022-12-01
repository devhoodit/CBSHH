from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple
from cyberbattle._env import cyberbattle_env

default_allow_rules = [
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
    m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
    m.FirewallRule("HTTP", m.RulePermission.ALLOW),
]

nodes = {
    "client": m.NodeInfo(
        services=[],
        value=0,
        vulnerabilities=dict(
            SearchSshConnection=m.VulnerabilityInfo(
                description="Connection to H's PC",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["hpc"]),
                reward_string="Connection to H's PC",
                cost=1.0,
            ),
            SearchInternetConnection=m.VulnerabilityInfo(
                description="Connection to Eclass",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["eclass", "github"]),
                reward_string="Connection to Internet (eclass, github)",
                cost=1.0
            ),
            CredScanBashHistory=m.VulnerabilityInfo(
                description="Scan bash history to get ssh cred",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="hpc", port="SSH", credential="SshCred") # leak ssh cred
                ]),
                reward_string="FLAG SSH credentials info leaked from user PC",
                cost=1.0
            )
        ),
        agent_installed=True,
        reimagable=False
    ),
    "github": m.NodeInfo(
        services=[m.ListeningService("HTTPS", allowedCredentials=["GithubCred"])],
        value=0,
        properties=['Github'],
        owned_string="FLAG Access personal github commit history",
        vulnerabilities=dict(
            CredScanGitHistorySudo=m.VulnerabilityInfo(
                description="Get sudo password",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="hpc[user=file]", port="sudo", credential="RootSudoPassword")
                ]),
                rates=m.Rates(successRate=0.5),
                cost=2.0
            ),
            CredScanGitHistorySu=m.VulnerabilityInfo(
                description="Get su password",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="hpc[user=file]", port="su", credential="UserSudoPassword")
                ]),
                rates=m.Rates(successRate=0.8),
                cost=1.0
            )
        )
    ),
    "hpc[user=file]": m.NodeInfo(
        services=[
            m.ListeningService("sudo", allowedCredentials=["RootSudoPassword"]),
            m.ListeningService("su", allowedCredentials=["UserSudoPassword"])
        ],
        value=50,
        properties=['Ubuntu'],
        owned_string="FLAG access permission to User",
        firewall=m.FirewallConfiguration(
            outgoing=default_allow_rules,
            incoming=[
                m.FirewallRule("su", m.RulePermission.BLOCK, reason="su can't access all root permission"),
                m.FirewallRule("sudo", m.RulePermission.ALLOW)
            ] + default_allow_rules
        ),
        vulnerabilities=dict(
            NavigateBrowserCookie=m.VulnerabilityInfo(
                description="Navigate Browser Cookie to get session id of github",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="eclass", port="HTTPS", credential="EclassSessionID")
                ]),
                rates=m.Rates(successRate=0.8),
                reward_string="Navigating Browser Cookie and get Eclass SessionID success"
            )
        )
    )
    ,
    "hpc": m.NodeInfo(
        services=[
            m.ListeningService("SSH", allowedCredentials=["SshCred"])
        ],
        firewall=m.FirewallConfiguration(
            incoming=default_allow_rules,
            outgoing=default_allow_rules + [
                m.FirewallRule("sudo", m.RulePermission.ALLOW)
            ]
        ),
        vulnerabilities=dict(
            CredScanBashHistory=m.VulnerabilityInfo(
                description="Scan bash history to get ssh cred",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="github", port="HTTPS", credential="GithubCred") # leak github id and credential
                ]),
                reward_string="FLAG H's Github Credential leaked",
                cost=1.0
            ),
            SearchInternetCookie=m.VulnerabilityInfo(
                description="Search Browser cookie to find eclass session id",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["hpc[user=file]"]),
                reward_string="Scan file to find Browser cookie info",
                cost=1.0
            )
        ),
        value=10,
        properties=["Ubuntu"],
        owned_string="FLAG H's PC owned"
    ),
    "eclass": m.NodeInfo(
        services=[
            m.ListeningService("HTTPS", allowedCredentials=["EclassSessionID"])
        ],
        vulnerabilities=dict(
            SearchExamClass=m.VulnerabilityInfo(
                description="Search to Exam",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["ExamPaper"]),
                reward_string="FLAG Enter eclass main",
                cost=1.0
            )
        ),
        value=70,
        properties=["eclass"],
        owned_string="FLAG Exam Paper"
    ),
    "ExamPaper": m.NodeInfo(
        services=[
            m.ListeningService("HTTPS", allowedCredentials=["EclassSessionID"])
        ],
        value=200,
        properties=["eclass"],
        owned_string="FLAG Get Exam Paper"
    ),
}

global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])

ENV_IDENTIFIERS = m.infer_constants_from_nodes(
    cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())),
    global_vulnerability_library)

def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=ENV_IDENTIFIERS
    )

class CyberBattleCBSHH(cyberbattle_env.CyberBattleEnv):
    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=new_environment(),
            **kwargs
        )