import click
import sys
import json
import os
import csv
from pathlib import Path
from datetime import datetime
from typing import Optional
from collections import Counter

from .vault import Vault
from .operations import OperationManager
from .exceptions import VaultError

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version="1.0.0")
def cli():
    """credvault: Secure offline credential vault for red-team operations"""
    pass


@cli.command()
@click.option("--yubikey", is_flag=True, help="Use YubiKey PIV for encryption")
@click.option("--passphrase", is_flag=True, help="Use passphrase for encryption")
def init(yubikey: bool, passphrase: bool):
    """Initialize a new credential vault"""
    try:
        if not yubikey and not passphrase:
            click.echo("Error: Must specify either --yubikey or --passphrase", err=True)
            sys.exit(1)

        vault = Vault()
        vault.initialize(use_yubikey=yubikey, use_passphrase=passphrase)
        click.echo("✓ Vault initialized successfully")
    except VaultError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('name')
@click.argument('type')
@click.option('--value', help='Credential value')
@click.option('--username', help='Username associated with credential')
@click.option('--domain', help='Domain/Realm')
@click.option('--operation', help='Operation name (defaults to current)')
@click.option('--notes', help='Additional notes')
@click.option('--tags', help='Comma-separated tags (e.g., "critical,admin,domain")')
def add(name: str, type: str, value: str = None, username: str = None, 
        domain: str = None, operation: str = None, notes: str = None, 
        tags: str = None):
    """Add a credential to the vault"""
    try:
        vault = Vault()
        vault.load()
        
        # Get current operation if not specified
        if not operation:
            operation = vault.get_current_operation()
        
        # Interactive mode if value not provided
        if value is None:
            import getpass
            click.echo(f"Adding credential: {name} ({type})")
            if operation:
                click.echo(f"Operation: {operation}")
            
            # Get value
            value = click.prompt("Value", hide_input=True)
            
            # Get optional fields if not provided
            if username is None:
                username = click.prompt("Username (optional)", default="", show_default=False)
                username = username if username else None
            
            if domain is None:
                domain = click.prompt("Domain/Realm (optional)", default="", show_default=False)
                domain = domain if domain else None
            
            if notes is None:
                notes = click.prompt("Notes (optional)", default="", show_default=False)
                notes = notes if notes else None
            
            if tags is None:
                tags_input = click.prompt("Tags (comma-separated, optional)", default="", show_default=False)
                tags = [t.strip() for t in tags_input.split(',') if t.strip()] if tags_input else None
        
        # Parse tags if provided as string
        tag_list = None
        if tags:
            if isinstance(tags, str):
                tag_list = [t.strip() for t in tags.split(',') if t.strip()]
            else:
                tag_list = tags
        
        vault.add_credential(
            name=name,
            type=type,
            value=value,
            username=username,
            domain=domain,
            notes=notes,
            tags=tag_list,
            operation=operation
        )
        
        click.echo(f"✓ Added '{name}' to vault")
        if operation:
            click.echo(f"  Operation: {operation}")
        
    except VaultError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('name')
@click.option('--clip', is_flag=True, help='Copy value to clipboard (10s timeout)')
@click.option('--format', type=click.Choice(['json', 'pretty', 'value-only']), 
              default='pretty', help='Output format')
def get(name: str, clip: bool, format: str):
    """Retrieve a credential from the vault"""
    try:
        vault = Vault()
        vault.load()
        credential = vault.get_credential(name)
        
        if clip:
            import pyperclip
            from .memory import secure_delayed_clear
            
            pyperclip.copy(credential['value'])
            click.echo("✓ Credential copied to clipboard (will clear in 10s)")
            secure_delayed_clear(credential['value'], 10)
        
        if format == 'value-only':
            click.echo(credential['value'])
        elif format == 'json':
            click.echo(json.dumps(credential, indent=2))
        else:  # pretty format
            click.echo(f"\n{'='*50}")
            click.echo(f"Credential: {credential['name']}")
            click.echo(f"{'='*50}")
            
            fields = [
                ('Type', credential.get('type')),
                ('Username', credential.get('username')),
                ('Domain', credential.get('domain')),
                ('Value', credential.get('value')),
                ('Added', credential.get('added')),
                ('Operation', credential.get('operation')),
                ('Tags', ', '.join(credential.get('tags', [])) if credential.get('tags') else None),
                ('Notes', credential.get('notes')),
            ]
            
            for label, value in fields:
                if value:
                    click.echo(f"{label:10}: {value}")
            
            click.echo(f"{'='*50}")
            
    except VaultError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('name')
@click.option('--new-name', help='Rename credential')
@click.option('--value', help='Update value')
@click.option('--username', help='Update username')
@click.option('--domain', help='Update domain')
@click.option('--operation', help='Update operation')
@click.option('--notes', help='Update notes')
@click.option('--add-tag', help='Add tag to credential')
@click.option('--remove-tag', help='Remove tag from credential')
def update(name: str, new_name: str = None, value: str = None, 
           username: str = None, domain: str = None, operation: str = None,
           notes: str = None, add_tag: str = None, remove_tag: str = None):
    """Update an existing credential"""
    try:
        vault = Vault()
        vault.load()
        
        # Get current credential
        current = vault.get_credential(name)
        
        # Update fields if provided
        updated_name = new_name if new_name is not None else current['name']
        updated_value = value if value is not None else current['value']
        updated_username = username if username is not None else current.get('username')
        updated_domain = domain if domain is not None else current.get('domain')
        updated_operation = operation if operation is not None else current.get('operation')
        updated_notes = notes if notes is not None else current.get('notes')
        
        # Handle tags
        updated_tags = current.get('tags', [])[:]
        if add_tag:
            if add_tag not in updated_tags:
                updated_tags.append(add_tag)
        if remove_tag and remove_tag in updated_tags:
            updated_tags.remove(remove_tag)
        
        # Delete old credential
        vault.delete_credential(name)
        
        # Add updated credential
        vault.add_credential(
            name=updated_name,
            type=current['type'],
            value=updated_value,
            username=updated_username,
            domain=updated_domain,
            notes=updated_notes,
            tags=updated_tags,
            operation=updated_operation
        )
        
        click.echo(f"✓ Updated credential '{name}'")
        
    except VaultError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--filter', help='Filter by any field (name, type, username, domain, notes, tags, operation)')
@click.option('--type', 'type_filter', help='Filter by credential type')
@click.option('--tag', help='Filter by tag')
@click.option('--domain', help='Filter by domain')
@click.option('--operation', 'op_filter', help='Filter by operation name')
@click.option('--format', type=click.Choice(['table', 'json', 'csv', 'simple']), default='table')
def list(filter: str = None, type_filter: str = None, tag: str = None, 
         domain: str = None, op_filter: str = None, format: str = 'table'):
    """List all credentials in the vault"""
    try:
        vault = Vault()
        vault.load()
        
        # Use the enhanced list_credentials method with filters
        credentials = vault.list_credentials(
            filter_type=type_filter,
            filter_domain=domain,
            filter_tag=tag,
            filter_query=filter,
            filter_operation=op_filter
        )
        
        if not credentials:
            click.echo("No credentials found" + 
                      (f" matching filters" if any([filter, type_filter, tag, domain, op_filter]) else " in vault"))
            return
        
        if format == 'json':
            click.echo(json.dumps(credentials, indent=2, default=str))
        elif format == 'csv':
            # CSV header
            click.echo("Name,Type,Username,Domain,Operation,Tags,Added,Notes")
            for cred in credentials:
                # Escape quotes in notes
                notes = str(cred.get('notes', '')).replace('"', '""')
                tags = ';'.join(cred.get('tags', []))
                username = cred.get('username', '')
                domain_val = cred.get('domain', '')
                operation_val = cred.get('operation', '')
                click.echo(f'"{cred["name"]}","{cred["type"]}","{username}","{domain_val}","{operation_val}","{tags}","{cred["added"]}","{notes}"')
        elif format == 'simple':
            # Simple list for scripting
            for cred in credentials:
                click.echo(f"{cred['name']} ({cred['type']})")
        else:  # table format
            try:
                from tabulate import tabulate
                table_data = []
                for cred in credentials:
                    table_data.append([
                        cred['name'],
                        cred['type'],
                        cred.get('username', ''),
                        cred.get('domain', ''),
                        cred.get('operation', ''),
                        ', '.join(cred.get('tags', []))[:30],
                        cred['added'][:16] if cred['added'] else ''
                    ])
                
                headers = ['Name', 'Type', 'Username', 'Domain', 'Operation', 'Tags', 'Added']
                click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))
                
                # Show summary
                click.echo(f"\nTotal: {len(credentials)} credentials")
                if credentials:
                    types_count = Counter([c['type'] for c in credentials])
                    click.echo("By type: " + ', '.join([f"{t}: {c}" for t, c in types_count.most_common()]))
                    
                    # Show operations if filtered
                    if op_filter:
                        click.echo(f"Operation: {op_filter}")
                    
            except ImportError:
                # Fallback if tabulate not installed
                for cred in credentials:
                    line = f"{cred['name']} ({cred['type']})"
                    if cred.get('username'):
                        line += f" - {cred['username']}"
                    if cred.get('domain'):
                        line += f" @ {cred['domain']}"
                    if cred.get('operation'):
                        line += f" [Op: {cred['operation']}]"
                    if cred.get('tags'):
                        line += f" [{', '.join(cred['tags'])}]"
                    click.echo(line)
            
    except VaultError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("output", type=click.Path())
def export(output: str):
    """Export vault to encrypted .age file"""
    try:
        vault = Vault()
        vault.load()
        vault.export(output)
        click.echo(f"✓ Vault exported to {output}")
    except VaultError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('query')
@click.option('--field', type=click.Choice(['all', 'name', 'value', 'username', 'domain', 'notes', 'tags', 'operation']), 
              default='all', help='Search in specific field')
@click.option('--case-sensitive', is_flag=True, help='Case sensitive search')
def search(query: str, field: str, case_sensitive: bool):
    """Search credentials in the vault"""
    try:
        vault = Vault()
        vault.load()
        credentials = vault.list_credentials()
        
        if not credentials:
            click.echo("Vault is empty")
            return
        
        results = []
        search_query = query if case_sensitive else query.lower()
        
        for cred in credentials:
            match = False
            
            if field == 'all' or field == 'name':
                target = cred['name'] if case_sensitive else cred['name'].lower()
                if search_query in target:
                    match = True
            
            if not match and (field == 'all' or field == 'value'):
                target = cred.get('value', '') if case_sensitive else cred.get('value', '').lower()
                if search_query in target:
                    match = True
            
            if not match and (field == 'all' or field == 'username'):
                target = cred.get('username', '') if case_sensitive else cred.get('username', '').lower()
                if search_query in target:
                    match = True
            
            if not match and (field == 'all' or field == 'domain'):
                target = cred.get('domain', '') if case_sensitive else cred.get('domain', '').lower()
                if search_query in target:
                    match = True
            
            if not match and (field == 'all' or field == 'notes'):
                target = cred.get('notes', '') if case_sensitive else cred.get('notes', '').lower()
                if search_query in target:
                    match = True
            
            if not match and (field == 'all' or field == 'operation'):
                target = cred.get('operation', '') if case_sensitive else cred.get('operation', '').lower()
                if search_query in target:
                    match = True
            
            if not match and (field == 'all' or field == 'tags'):
                tags = cred.get('tags', [])
                for tag in tags:
                    target = tag if case_sensitive else tag.lower()
                    if search_query in tag:
                        match = True
                        break
            
            if match:
                results.append(cred)
        
        if not results:
            click.echo(f"No credentials found for query: '{query}'")
            return
        
        click.echo(f"Found {len(results)} credentials:")
        for cred in results:
            line = f"  {cred['name']} ({cred['type']})"
            if cred.get('username'):
                line += f" - User: {cred['username']}"
            if cred.get('domain'):
                line += f" @ {cred['domain']}"
            if cred.get('operation'):
                line += f" [Op: {cred['operation']}]"
            if cred.get('tags'):
                line += f" [Tags: {', '.join(cred['tags'])}]"
            click.echo(line)
            
    except VaultError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
def verify():
    """Verify vault integrity"""
    try:
        vault = Vault()
        vault.load()
        if vault.verify_integrity():
            click.echo("✓ Vault integrity verified")
        else:
            click.echo("✗ Vault integrity check failed", err=True)
            sys.exit(1)
    except VaultError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--from",
    "source",
    type=click.Choice(["mimikatz", "impacket", "cme"]),
    required=True,
    help="Source tool format",
)
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False))
def importer(source: str, input_file: str):
    """Import credentials from common tools (mimikatz, impacket, cme)"""
    try:
        from .importers import import_mimikatz, import_impacket, import_cme

        vault = Vault()
        vault.load()

        # Dispatch to parser
        if source == "mimikatz":
            entries = import_mimikatz(input_file)
        elif source == "impacket":
            entries = import_impacket(input_file)
        elif source == "cme":
            entries = import_cme(input_file)
        else:
            raise VaultError(f"Unsupported source: {source}")

        if not entries:
            click.echo("⚠️  No credentials found in input file")
            return

        added = 0
        for entry in entries:
            try:
                vault.add_credential(entry["name"], entry["type"], entry["value"])
                added += 1
            except VaultError as e:
                click.echo(f"  Skipping '{entry['name']}': {e}", err=True)

        click.echo(f"✓ Imported {added} credential(s) from {source}")

    except VaultError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Parser error: {e}", err=True)
        sys.exit(1)


@cli.command()
def status():
    """Show current vault and operation status"""
    try:
        vault = Vault()
        
        # Try to load vault
        try:
            vault.load()
            click.echo("✓ Vault: Loaded and unlocked")
            
            # Show operation status
            current_op = vault.get_current_operation()
            if current_op:
                click.echo(f"📁 Operation: {current_op} (active)")
                
                # Count credentials in current operation
                op_manager = OperationManager()
                op_manager.load_operations()
                operation = op_manager.get_operation(current_op)
                if operation:
                    click.echo(f"   Credentials: {len(operation.credential_ids)}")
                
                # Show recent additions
                all_creds = vault.list_credentials(filter_operation=current_op)
                if all_creds:
                    recent = sorted(all_creds, key=lambda x: x['added'], reverse=True)[:3]
                    click.echo("   Recent:")
                    for cred in recent:
                        click.echo(f"     • {cred['name']} ({cred['type']})")
            else:
                click.echo("📁 Operation: None (use 'credvault op start' or 'credvault op switch')")
            
            # Show vault stats
            all_creds = vault.list_credentials()
            click.echo(f"\n📊 Vault Statistics:")
            click.echo(f"   Total credentials: {len(all_creds)}")
            
            # Count by type
            types = Counter([c['type'] for c in all_creds])
            click.echo(f"   By type: {', '.join([f'{t}: {c}' for t, c in types.most_common(3)])}")
            
            # Operations count
            op_manager = OperationManager()
            op_manager.load_operations()
            all_ops = op_manager.list_operations()
            click.echo(f"   Operations: {len(all_ops)} (active: {len([o for o in all_ops if o.status == 'active'])})")
            
        except VaultError as e:
            click.echo(f"🔒 Vault: Locked ({str(e)})")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# ============================================================================
# OPERATION COMMANDS
# ============================================================================

@cli.group()
def op():
    """Operation/Engagement management"""
    pass


@op.command(name="start")
@click.argument('name')
@click.option('--client', help='Client name')
@click.option('--description', help='Operation description')
@click.option('--tags', help='Comma-separated tags')
def op_start(name: str, client: str, description: str, tags: str):
    """Start a new operation/engagement"""
    try:
        op_manager = OperationManager()
        op_manager.load_operations()
        
        # Parse tags
        tag_list = None
        if tags:
            tag_list = [t.strip() for t in tags.split(',') if t.strip()]
        
        # Create operation
        operation = op_manager.create_operation(
            name=name,
            client=client or "",
            description=description or "",
            tags=tag_list
        )
        
        # Set as current
        op_manager.set_current_operation(operation.name)
        
        click.echo(f"✓ Operation '{name}' started")
        click.echo(f"  Client: {client or 'N/A'}")
        click.echo(f"  Description: {description or 'N/A'}")
        if tag_list:
            click.echo(f"  Tags: {', '.join(tag_list)}")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@op.command(name="switch")
@click.argument('name')
def op_switch(name: str):
    """Switch to a different operation"""
    try:
        vault = Vault()
        vault.set_current_operation(name)
        click.echo(f"✓ Switched to operation: {name}")
        
        # Show operation info
        op_manager = OperationManager()
        op_manager.load_operations()
        operation = op_manager.get_operation(name)
        if operation:
            click.echo(f"  Status: {operation.status}")
            click.echo(f"  Created: {operation.created[:10]}")
            if operation.tags:
                click.echo(f"  Tags: {', '.join(operation.tags)}")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@op.command(name="list")
@click.option('--status', type=click.Choice(['active', 'archived', 'all']), 
              default='active', help='Filter by status')
@click.option('--tag', help='Filter by tag')
@click.option('--format', type=click.Choice(['table', 'json', 'simple']), 
              default='table')
def op_list(status: str, tag: str, format: str):
    """List all operations"""
    try:
        op_manager = OperationManager()
        op_manager.load_operations()
        
        # Get current operation
        current = op_manager.get_current_operation()
        current_name = current.name if current else None
        
        # Filter operations
        ops = op_manager.list_operations(
            status=None if status == 'all' else status,
            tag=tag
        )
        
        if not ops:
            click.echo("No operations found")
            return
        
        if format == 'json':
            click.echo(json.dumps([op.to_dict() for op in ops], indent=2))
        elif format == 'simple':
            for op in ops:
                prefix = "→ " if op.name == current_name else "  "
                click.echo(f"{prefix}{op.name} ({op.client})")
        else:  # table format
            try:
                from tabulate import tabulate
                table_data = []
                for op in ops:
                    prefix = "→ " if op.name == current_name else ""
                    table_data.append([
                        prefix + op.name,
                        op.client[:20],
                        op.status,
                        len(op.credential_ids),
                        ', '.join(op.tags)[:30],
                        op.created[:10],
                        op.modified[:10]
                    ])
                
                headers = ['Name', 'Client', 'Status', 'Creds', 'Tags', 'Created', 'Modified']
                click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))
                
                click.echo(f"\nTotal: {len(ops)} operations")
                if current_name:
                    click.echo(f"Current: {current_name}")
                
            except ImportError:
                # Fallback
                for op in ops:
                    prefix = "→ " if op.name == current_name else "  "
                    click.echo(f"{prefix}{op.name} - {op.client} ({op.status})")
                    click.echo(f"    Creds: {len(op.credential_ids)}, Tags: {', '.join(op.tags)}")
                    click.echo(f"    Created: {op.created[:10]}, Modified: {op.modified[:10]}")
                    click.echo()
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@op.command(name="info")
@click.argument('name', required=False)
def op_info(name: str):
    """Show operation details"""
    try:
        op_manager = OperationManager()
        op_manager.load_operations()
        
        # If no name provided, show current
        if not name:
            current = op_manager.get_current_operation()
            if not current:
                click.echo("No current operation. Use 'credvault op start' or 'credvault op switch'")
                return
            name = current.name
        
        operation = op_manager.get_operation(name)
        if not operation:
            click.echo(f"Operation '{name}' not found")
            return
        
        # Show operation details
        click.echo(f"\n{'='*60}")
        click.echo(f"Operation: {operation.name}")
        click.echo(f"{'='*60}")
        click.echo(f"Client:       {operation.client}")
        click.echo(f"Description:  {operation.description}")
        click.echo(f"Status:       {operation.status}")
        click.echo(f"Created:      {operation.created}")
        click.echo(f"Modified:     {operation.modified}")
        click.echo(f"Tags:         {', '.join(operation.tags)}")
        click.echo(f"Credentials:  {len(operation.credential_ids)}")
        
        # Show metadata
        if operation.metadata:
            click.echo(f"\nMetadata:")
            for key, value in operation.metadata.items():
                click.echo(f"  {key}: {value}")
        
        # List recent credentials
        if operation.credential_ids:
            click.echo(f"\nRecent credentials:")
            vault = Vault()
            vault.load()
            
            # Get last 5 credentials
            recent_creds = []
            for cred_id in operation.credential_ids[-5:]:
                try:
                    cred = vault.get_credential(cred_id)
                    recent_creds.append(cred)
                except:
                    continue
            
            for cred in recent_creds[-5:]:
                click.echo(f"  • {cred['name']} ({cred['type']})")
                if cred.get('username'):
                    click.echo(f"    User: {cred['username']}")
                if cred.get('domain'):
                    click.echo(f"    Domain: {cred['domain']}")
        
        click.echo(f"{'='*60}")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@op.command(name="archive")
@click.argument('name')
def op_archive(name: str):
    """Archive/completed an operation"""
    try:
        op_manager = OperationManager()
        op_manager.load_operations()
        
        op_manager.archive_operation(name)
        click.echo(f"✓ Operation '{name}' archived")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@op.command(name="delete")
@click.argument('name')
@click.option('--force', is_flag=True, help='Force delete even if current')
def op_delete(name: str, force: bool):
    """Delete an operation"""
    try:
        op_manager = OperationManager()
        op_manager.load_operations()
        
        # Confirm deletion
        if not force:
            click.confirm(f"Delete operation '{name}'? This does NOT delete credentials.", abort=True)
        
        op_manager.delete_operation(name, force=force)
        click.echo(f"✓ Operation '{name}' deleted")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@op.command(name="export")
@click.argument('name')
@click.argument('output', type=click.Path())
@click.option('--format', type=click.Choice(['json', 'html', 'csv', 'report']), 
              default='json', help='Export format')
def op_export(name: str, output: str, format: str):
    """Export operation data"""
    try:
        op_manager = OperationManager()
        op_manager.load_operations()
        
        operation = op_manager.get_operation(name)
        if not operation:
            click.echo(f"Operation '{name}' not found")
            return
        
        # Load vault to get credential details
        vault = Vault()
        vault.load()
        
        # Get all operation credentials
        operation_creds = []
        for cred_id in operation.credential_ids:
            try:
                cred = vault.get_credential(cred_id)
                operation_creds.append(cred)
            except:
                continue
        
        if format == 'json':
            export_data = {
                'operation': operation.to_dict(),
                'credentials': operation_creds,
                'exported': datetime.utcnow().isoformat() + 'Z',
                'stats': {
                    'total_credentials': len(operation_creds),
                    'by_type': {},
                    'by_domain': {}
                }
            }
            
            # Add statistics
            for cred in operation_creds:
                cred_type = cred['type']
                export_data['stats']['by_type'][cred_type] = export_data['stats']['by_type'].get(cred_type, 0) + 1
                
                if cred.get('domain'):
                    domain = cred['domain']
                    export_data['stats']['by_domain'][domain] = export_data['stats']['by_domain'].get(domain, 0) + 1
            
            with open(output, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            click.echo(f"✓ Exported operation '{name}' to {output} (JSON)")
            
        elif format == 'csv':
            with open(output, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow(['Name', 'Type', 'Username', 'Domain', 'Value', 'Tags', 'Notes', 'Added'])
                
                # Write credentials
                for cred in operation_creds:
                    writer.writerow([
                        cred['name'],
                        cred['type'],
                        cred.get('username', ''),
                        cred.get('domain', ''),
                        cred['value'],
                        ';'.join(cred.get('tags', [])),
                        cred.get('notes', ''),
                        cred['added']
                    ])
            
            click.echo(f"✓ Exported {len(operation_creds)} credentials to {output} (CSV)")
            
        elif format == 'html':
            # Simple HTML report
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Operation Report: {operation.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .operation-info {{ background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .credential {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .type-ntlm {{ border-left: 5px solid #dc3545; }}
        .type-password {{ border-left: 5px solid #28a745; }}
        .type-kerberos {{ border-left: 5px solid #007bff; }}
        pre {{ background: #f8f9fa; padding: 10px; border-radius: 3px; }}
    </style>
</head>
<body>
    <h1> Operation Report: {operation.name}</h1>
    
    <div class="operation-info">
        <h2>Operation Details</h2>
        <p><strong>Client:</strong> {operation.client}</p>
        <p><strong>Description:</strong> {operation.description}</p>
        <p><strong>Status:</strong> {operation.status}</p>
        <p><strong>Created:</strong> {operation.created}</p>
        <p><strong>Credentials:</strong> {len(operation_creds)}</p>
        <p><strong>Tags:</strong> {', '.join(operation.tags)}</p>
    </div>
    
    <h2>Credentials ({len(operation_creds)})</h2>
"""
            
            for cred in operation_creds:
                type_class = f"type-{cred['type']}"
                html += f"""
    <div class="credential {type_class}">
        <h3>{cred['name']} ({cred['type']})</h3>
        <p><strong>Username:</strong> {cred.get('username', 'N/A')}</p>
        <p><strong>Domain:</strong> {cred.get('domain', 'N/A')}</p>
        <p><strong>Added:</strong> {cred['added']}</p>
        <p><strong>Value:</strong></p>
        <pre>{cred['value']}</pre>
"""
                
                if cred.get('notes'):
                    html += f"<p><strong>Notes:</strong> {cred['notes']}</p>"
                
                if cred.get('tags'):
                    html += f"<p><strong>Tags:</strong> {', '.join(cred['tags'])}</p>"
                
                html += "</div>"
            
            html += f"""
    <hr>
    <p>Report generated: {datetime.utcnow().isoformat()}Z</p>
    <p>Tool: CredVault - Secure Credential Manager</p>
</body>
</html>"""
            
            with open(output, 'w') as f:
                f.write(html)
            
            click.echo(f"✓ Exported operation report to {output} (HTML)")
            
        elif format == 'report':
            # Text report for console
            report = f"""
{'='*80}
OPERATION REPORT: {operation.name}
{'='*80}
Client:       {operation.client}
Description:  {operation.description}
Status:       {operation.status}
Created:      {operation.created}
Modified:     {operation.modified}
Tags:         {', '.join(operation.tags)}
Credentials:  {len(operation_creds)}

{'='*80}
CREDENTIALS
{'='*80}
"""
            
            for cred in operation_creds:
                report += f"\n[{cred['type'].upper()}] {cred['name']}\n"
                report += f"{'-'*40}\n"
                if cred.get('username'):
                    report += f"Username: {cred['username']}\n"
                if cred.get('domain'):
                    report += f"Domain:   {cred['domain']}\n"
                report += f"Value:    {cred['value'][:50]}...\n"
                if cred.get('tags'):
                    report += f"Tags:     {', '.join(cred['tags'])}\n"
                if cred.get('notes'):
                    report += f"Notes:    {cred['notes']}\n"
                report += f"Added:    {cred['added'][:19]}\n"
            
            report += f"\n{'='*80}\n"
            report += f"Report generated: {datetime.utcnow().isoformat()}Z\n"
            report += f"{'='*80}"
            
            with open(output, 'w') as f:
                f.write(report)
            
            click.echo(f"✓ Exported operation report to {output}")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@op.command(name="update")
@click.argument('name')
@click.option('--client', help='Update client name')
@click.option('--description', help='Update description')
@click.option('--status', type=click.Choice(['active', 'archived']), 
              help='Update status')
@click.option('--add-tag', help='Add tag to operation')
@click.option('--remove-tag', help='Remove tag from operation')
def op_update(name: str, client: str, description: str, status: str, 
             add_tag: str, remove_tag: str):
    """Update operation details"""
    try:
        op_manager = OperationManager()
        op_manager.load_operations()
        
        operation = op_manager.get_operation(name)
        if not operation:
            click.echo(f"Operation '{name}' not found")
            return
        
        updated = False
        
        if client is not None:
            operation.client = client
            updated = True
        
        if description is not None:
            operation.description = description
            updated = True
        
        if status is not None:
            operation.status = status
            updated = True
        
        if add_tag:
            if add_tag not in operation.tags:
                operation.tags.append(add_tag)
                updated = True
        
        if remove_tag and remove_tag in operation.tags:
            operation.tags.remove(remove_tag)
            updated = True
        
        if updated:
            op_manager.save_operation(operation)
            click.echo(f"✓ Updated operation '{name}'")
        else:
            click.echo("No changes made")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()