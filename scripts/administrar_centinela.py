"""Provisionar o recuperar cuentas desde la consola privada del servidor."""
import argparse
import getpass
import os
from pathlib import Path

from centinela_identity import IdentityStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path,
                        default=Path(os.environ.get('CENTINELA_DATA_DIR', '/var/lib/centinela')))
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('crear-admin', help='Crear una cuenta de administrador')
    create.add_argument('username')
    create.add_argument('--nombre', required=True)
    create.add_argument('--adoptar-historial', action='store_true',
                        help='Asignar el historial original a esta cuenta, solo una vez')
    reset = commands.add_parser('restablecer', help='Restablecer contraseña y revocar sesiones')
    reset.add_argument('username')
    args = parser.parse_args()
    store = IdentityStore(args.data_dir)
    owner_file = store.directory / 'legacy-owner'
    if args.command == 'crear-admin' and args.adoptar_historial and owner_file.exists():
        parser.error('El historial original ya tiene propietario.')
    user = next((u for u in store.users() if u['username'] == args.username.strip().lower()), None)
    if args.command == 'restablecer' and not user:
        parser.error('El usuario no existe.')
    password = getpass.getpass('Nueva contraseña (mínimo 8 caracteres): ')
    if password != getpass.getpass('Confirmar contraseña: '):
        parser.error('Las contraseñas no coinciden.')
    try:
        if args.command == 'crear-admin':
            uid = store.create_user(args.username, args.nombre, password, 'admin', 'server-console')
            if args.adoptar_historial:
                with owner_file.open('x') as file:
                    file.write(uid + '\n')
                owner_file.chmod(0o600)
        else:
            store.update_user('server-console', user['id'], user['role'], bool(user['active']), password)
    except ValueError as exc:
        parser.error(str(exc))
    print('Cuenta actualizada. La contraseña no se muestra ni se guarda en texto plano.')


if __name__ == '__main__':
    main()
