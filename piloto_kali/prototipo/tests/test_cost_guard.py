"""El control monetario se prueba sin transporte ni clave API."""
from decimal import Decimal
import pytest
from auditoria.openai_provider import OpenAIScheduler


def scheduler(calls=(),limit=2):
    value=object.__new__(OpenAIScheduler)
    value.calls=list(calls);value.complete=True;value.max_cost_usd=limit
    return value


def test_conservative_reservation_includes_all_billable_output():
    value=scheduler()
    cap,cost=value.affordable_generation(1000,2048)
    assert cap==2048
    assert Decimal(str(cost))==Decimal('0.0055')+Decimal(2048)*Decimal('0.0000165')
    # El presupuesto normal60k es menor queUSD2 aun bajo esta envolvente.
    cap,cost=value.affordable_generation(59000,1000)
    assert cap==1000 and cost<2


def test_remaining_budget_reduces_output_before_generation():
    value=scheduler([{'generation_sent':True,'input_tokens':100000,'provider_output_tokens':85000}])
    cap,reservation=value.affordable_generation(100,4096)
    assert 256<=cap<4096
    spent=Decimal(100000)*Decimal('0.0000055')+Decimal(85000)*Decimal('0.0000165')
    assert spent+Decimal(str(reservation))<=2
    assert spent+Decimal(str(reservation))+Decimal('0.0000165')>2


def test_insufficient_or_unknown_cost_stops_before_generation():
    with pytest.raises(RuntimeError,match='cost_budget_exhausted'):
        scheduler(limit=.0001).affordable_generation(1,256)
    with pytest.raises(RuntimeError,match='usage_unavailable'):
        scheduler([{'generation_sent':True,'input_tokens':10,'provider_output_tokens':None}]).affordable_generation(1,256)
    value=scheduler();value.complete=False
    with pytest.raises(RuntimeError,match='usage_unavailable'):value.affordable_generation(1,256)
