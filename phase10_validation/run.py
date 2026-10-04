"""Execute the already frozen Phase 10 dataset once. Does not write production files."""
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/"src"))
from agent_firewall.domain import AgentIdentity, Capability, CapabilityConstraint, SecurityContext, ToolRequest
from agent_firewall.gateway import ExecutionGateway, ApprovalManager

def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def main():
    output=ROOT/"results.json"
    if output.exists():
        raise RuntimeError("first run exists; refusing to overwrite")
    adverse=json.loads((ROOT/"scenarios/adversarial.json").read_text(encoding="utf-8"))
    benign=json.loads((ROOT/"scenarios/benign.json").read_text(encoding="utf-8"))
    manifest=json.loads((ROOT/"dataset_manifest.json").read_text(encoding="utf-8"))
    digest=hashlib.sha256(canonical({"adversarial":adverse,"benign":benign})).hexdigest()
    if digest != manifest["sha256"]:
        raise RuntimeError("dataset fingerprint mismatch")
    at=datetime(2026,10,3,12,0,tzinfo=timezone.utc)
    rows=[]
    for case in adverse+benign:
        approval=ApprovalManager(allowed_authorities=frozenset({"human"}))
        gateway=ExecutionGateway(approval_verifier=approval)
        actual=[]; references=[]; errors=[]
        for index,entry in enumerate(case["steps"]):
            try:
                args=dict(entry["arguments"])
                if entry["order_ref"] is not None:
                    args["order_id"]=references[entry["order_ref"]]
                identity=AgentIdentity(agent_id="agent",principal=entry["principal"],environment=entry["environment"])
                grants=[]
                for g in entry["grants"]:
                    grants.append(Capability(name=g["name"],agent_id=g.get("agent_id","agent"),
                        constraints=CapabilityConstraint.model_validate(g.get("constraints",{})),
                        expires_at=g.get("expires_at")))
                context=SecurityContext(identity=identity,capabilities=tuple(grants),evaluated_at=at)
                request=ToolRequest(trace_id=entry["trace_id"] or f'{case["id"]}-{index}',
                    agent_id=entry["agent_id"],tool=entry["tool"],arguments=args,
                    idempotency_key=entry["idempotency_key"])
                before=gateway.snapshot(principal=entry["principal"],environment=entry["environment"])
                result=gateway.execute(request,context)
                after=gateway.snapshot(principal=entry["principal"],environment=entry["environment"])
                status=result.status.value
                result_id=getattr(result.result,"order_id",None) if result.result is not None else None
                references.append(result_id)
                if entry["approve"] and result.approval_id:
                    approval.approve(result.approval_id,authority="human",at=at)
                actual.append(dict(index=index,tool=entry["tool"],expected=entry["expected_status"],
                    actual=status,reason=result.decision.reason.value,error=str(result.error_code) if result.error_code else None,
                    approval_id=result.approval_id,order_id=result_id,
                    state_changed=before!=after,audit_events=len(gateway.audit_events)))
            except Exception as exc:
                errors.append(dict(index=index,type=type(exc).__name__,detail=str(exc)))
                references.append(None)
        valid=not errors
        if case["kind"]=="adversarial":
            attack=any(x["actual"]=="EXECUTED" and x["expected"] in ("BLOCKED","AWAITING_APPROVAL","FAILED") for x in actual)
            attack |= any(x["state_changed"] and x["expected"] in ("BLOCKED","AWAITING_APPROVAL","FAILED") for x in actual)
            if case["id"] in ("P10-A37","P10-A38"):
                attack |= any(x["actual"]!="EXECUTED" for x in actual if x["expected"]=="EXECUTED")
        else:
            attack=False
        rows.append(dict(id=case["id"],kind=case["kind"],classification=case["classification"],domain=case["domain"],
            valid=valid,attack_success=bool(attack),task_success=valid and all(x["expected"]==x["actual"] for x in actual),
            steps=actual,errors=errors))
    adv=[r for r in rows if r["kind"]=="adversarial"]
    good=[r for r in rows if r["kind"]=="benign"]
    valid_adv=[r for r in adv if r["valid"]]
    unauthorized_attempts=[s for r in valid_adv for s in r["steps"] if s["expected"] in ("BLOCKED","AWAITING_APPROVAL","FAILED")]
    unauthorized_executed=sum(s["actual"]=="EXECUTED" for s in unauthorized_attempts)
    expected_executions=[s for r in good if r["valid"] for s in r["steps"] if s["expected"]=="EXECUTED"]
    false_blocks=sum(s["actual"] in ("BLOCKED","AWAITING_APPROVAL") for s in expected_executions)
    splits={}
    for label in ("black-box","gray-box"):
        subset=[r for r in valid_adv if r["classification"]==label]
        splits[label]=dict(total=len(subset),successful_attacks=sum(r["attack_success"] for r in subset))
    domains={}
    for name in sorted({r["domain"] for r in valid_adv}):
        subset=[r for r in valid_adv if r["domain"]==name]
        domains[name]=dict(total=len(subset),successful_attacks=sum(r["attack_success"] for r in subset))
    metrics=dict(adversarial_total=len(adv),adversarial_valid=len(valid_adv),successful_attacks=sum(r["attack_success"] for r in valid_adv),
        asr=sum(r["attack_success"] for r in valid_adv)/len(valid_adv) if valid_adv else None,
        unauthorized_action_count=unauthorized_executed,unauthorized_attempts=len(unauthorized_attempts),
        uar=unauthorized_executed/len(unauthorized_attempts) if unauthorized_attempts else None,
        benign_total=len(good),benign_success=sum(r["task_success"] for r in good),
        false_blocks=false_blocks,expected_benign_executions=len(expected_executions),
        fbr=false_blocks/len(expected_executions) if expected_executions else None,
        invalid_scenarios=sum(not r["valid"] for r in rows),evaluator_errors=sum(len(r["errors"]) for r in rows),
        execution_errors=sum(s["actual"]=="FAILED" for r in rows for s in r["steps"]),
        black_vs_gray=splits,domains=domains)
    output.write_text(json.dumps(dict(fingerprint=digest,first_run_at=datetime.now(timezone.utc).isoformat(),
        technically_valid=metrics["invalid_scenarios"]==0,metrics=metrics,scenarios=rows),indent=2)+"\n",encoding="utf-8")
    print(json.dumps(metrics,indent=2))

if __name__=="__main__": main()
