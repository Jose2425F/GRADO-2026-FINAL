"""El transporte de negativos debe interpretar el rechazo real del servicio."""
import json
import socket
import struct
import threading

import pytest

from tesis.pruebas_roles import _rpc


@pytest.mark.parametrize('broker',[True,False])
def test_role_probe_reads_real_service_framing(tmp_path,broker):
    path=tmp_path/'endpoint.sock';server=socket.socket(socket.AF_UNIX)
    server.bind(str(path));server.listen(1)
    request={'args':['id'],'timeout':1,'password':None}
    response={'error':'broker_operation_denied'} if broker else {'ok':False,'reason':'worker_profile_denied'}
    observed=[]
    def serve():
        with server:
            connection,_=server.accept()
            with connection:
                connection.settimeout(2)
                if broker:
                    data=connection.makefile('rb').readline(4096)
                else:
                    size=struct.unpack('!I',connection.recv(4))[0];data=connection.recv(size)
                observed.append(json.loads(data))
                raw=json.dumps(response).encode()
                connection.sendall(raw+b'\n' if broker else struct.pack('!I',len(raw))+raw)
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    assert _rpc(path,request,broker=broker)==response
    thread.join(timeout=3);assert not thread.is_alive()
    assert observed==[request]
