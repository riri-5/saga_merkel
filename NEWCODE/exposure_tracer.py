"""
Compromise exposure tracing over the SAGA interaction ledger.
"""
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set

from saga.security.interaction_ledger import InteractionLedger


class ExposureTracer:
    def __init__(self, ledger: Optional[InteractionLedger] = None):
        self.ledger = ledger or InteractionLedger()

    def get_interaction_neighbors(self, agent_id: str) -> List[dict]:
        neighbors = []
        for record in self.ledger.load_records():
            if record.get("source_agent") == agent_id:
                neighbors.append({
                    "agent_id": record.get("destination_agent"),
                    "timestamp": record.get("timestamp"),
                    "interaction_id": record.get("interaction_id"),
                    "interaction_hash": record.get("interaction_hash"),
                    "session_id": record.get("session_id"),
                })
        return neighbors

    def build_exposure_graph(self, agent_id: str) -> Dict[str, dict]:
        records = sorted(self.ledger.load_records(), key=lambda item: item.get("timestamp", 0))
        adjacency = defaultdict(list)
        for record in records:
            adjacency[record.get("source_agent")].append(record)

        graph = {
            agent_id: {
                "depth": 0,
                "first_exposure_timestamp": None,
                "via": None,
                "children": [],
            }
        }
        queue = deque([agent_id])
        visited: Set[str] = {agent_id}

        while queue:
            current = queue.popleft()
            current_depth = graph[current]["depth"]
            for record in adjacency.get(current, []):
                neighbor = record.get("destination_agent")
                graph[current]["children"].append({
                    "agent_id": neighbor,
                    "interaction_id": record.get("interaction_id"),
                    "interaction_hash": record.get("interaction_hash"),
                    "timestamp": record.get("timestamp"),
                    "session_id": record.get("session_id"),
                })
                if neighbor not in visited:
                    visited.add(neighbor)
                    graph[neighbor] = {
                        "depth": current_depth + 1,
                        "first_exposure_timestamp": record.get("timestamp"),
                        "via": {
                            "source_agent": current,
                            "interaction_id": record.get("interaction_id"),
                            "interaction_hash": record.get("interaction_hash"),
                            "timestamp": record.get("timestamp"),
                            "session_id": record.get("session_id"),
                        },
                        "children": [],
                    }
                    queue.append(neighbor)
        return graph

    def trace_exposure(self, agent_id: str) -> Dict[str, object]:
        graph = self.build_exposure_graph(agent_id)
        directly_exposed = sorted(set(
            child["agent_id"]
            for child in graph.get(agent_id, {}).get("children", [])
            if child["agent_id"] != agent_id
        ))
        indirectly_exposed = sorted(
            node
            for node, metadata in graph.items()
            if node != agent_id and metadata.get("depth", 0) > 1
        )
        max_depth = max((metadata.get("depth", 0) for metadata in graph.values()), default=0)
        return {
            "compromised_agent": agent_id,
            "directly_exposed": directly_exposed,
            "indirectly_exposed": indirectly_exposed,
            "exposure_depth": max_depth,
            "graph": graph,
        }

    def propagate_compromise_alert(self, compromised_agent: str) -> Dict[str, object]:
        report = self.trace_exposure(compromised_agent)
        integrity = self.ledger.verify_ledger_integrity()
        potentially_compromised = sorted(
            set(report["directly_exposed"]) | set(report["indirectly_exposed"])
        )
        report.update({
            "potentially_compromised_agents": potentially_compromised,
            "ledger_integrity": "VALID" if integrity["valid"] else "INVALID",
            "ledger_integrity_report": integrity,
            "merkle_root": integrity.get("merkle_root"),
        })
        return report


def get_interaction_neighbors(agent_id: str, ledger: Optional[InteractionLedger] = None) -> List[dict]:
    return ExposureTracer(ledger).get_interaction_neighbors(agent_id)


def build_exposure_graph(agent_id: str, ledger: Optional[InteractionLedger] = None) -> Dict[str, dict]:
    return ExposureTracer(ledger).build_exposure_graph(agent_id)


def trace_exposure(agent_id: str, ledger: Optional[InteractionLedger] = None) -> Dict[str, object]:
    return ExposureTracer(ledger).trace_exposure(agent_id)


def propagate_compromise_alert(compromised_agent: str, ledger: Optional[InteractionLedger] = None) -> Dict[str, object]:
    return ExposureTracer(ledger).propagate_compromise_alert(compromised_agent)
