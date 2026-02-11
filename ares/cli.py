"""Click-based CLI for the Vulnerability-Lookup API."""

from __future__ import annotations

import functools
import json
import sys
import typing as t

import click

from .client import VulnLookup
from .exceptions import AresError
from .exceptions import HTTPError

F = t.TypeVar("F", bound=t.Callable[..., t.Any])

def get_client(ctx: click.Context) -> VulnLookup:
    """Return the shared :class:`VulnLookup` client, creating it lazily."""
    if "client" not in ctx.obj:
        ctx.obj["client"] = VulnLookup(
            base_url=ctx.obj["base_url"],
            api_key=ctx.obj["api_key"],
            timeout=ctx.obj["timeout"],
        )
        ctx.call_on_close(ctx.obj["client"].close)
    return ctx.obj["client"]

def output_json(ctx: click.Context, data: t.Any) -> None:
    """Write *data* as JSON to stdout."""
    compact = ctx.obj.get("compact", False)
    if compact or not sys.stdout.isatty():
        text = json.dumps(data, separators=(",", ":"))
    else:
        text = json.dumps(data, indent=2)
    click.echo(text)

def handle_errors(fn: F) -> F:
    """Catch client exceptions and convert to :class:`click.ClickException`."""
    @functools.wraps(fn)
    def wrapper(*args: t.Any, **kwargs: t.Any) -> t.Any:
        try:
            return fn(*args, **kwargs)
        except HTTPError as exc:
            raise click.ClickException(f"HTTP {exc.status_code}: {exc.message}")
        except AresError as exc:
            raise click.ClickException(str(exc))
    return wrapper  # type: ignore[return-value]

def pagination_options(fn: F) -> F:
    """Add ``--page`` and ``--per-page`` options."""
    fn = click.option("--page", type=int, default=None, help="Page number.")(fn)
    fn = click.option("--per-page", type=int, default=None, help="Results per page.")(fn)
    return fn

def _flag_or_none(value: bool) -> bool | None:
    """Convert a boolean flag to ``True`` or ``None``."""
    return True if value else None

@click.group()
@click.option("--api-key", envvar="ARES_API_KEY", default=None,
              help="API key (or set ARES_API_KEY).")
@click.option("--base-url", default=None,
              help="Base URL for the API.")
@click.option("--timeout", type=int, default=120,
              help="Request timeout in seconds.")
@click.option("--compact", is_flag=True, default=False,
              help="Force compact JSON output.")
@click.version_option(package_name="ares")
@click.pass_context
def cli(ctx, api_key, base_url, timeout, compact):
    """ares-cli — query the Vulnerability-Lookup API from the terminal."""
    ctx.ensure_object(dict)
    ctx.obj["api_key"] = api_key
    ctx.obj["base_url"] = base_url
    ctx.obj["timeout"] = timeout
    ctx.obj["compact"] = compact

@cli.command()
@click.argument("vendor", required=False, default=None)
@click.pass_context
@handle_errors
def browse(ctx, vendor):
    """List known vendors, or products for a specific vendor."""
    data = get_client(ctx).browse(vendor)
    output_json(ctx, data)

@cli.command()
@click.argument("cve_id")
@click.pass_context
@handle_errors
def epss(ctx, cve_id):
    """Get the EPSS score for a vulnerability."""
    data = get_client(ctx).epss(cve_id)
    output_json(ctx, data)

@cli.command()
@click.argument("cve_id")
@click.pass_context
@handle_errors
def rulezet(ctx, cve_id):
    """Get rules associated with a vulnerability."""
    data = get_client(ctx).rulezet(cve_id)
    output_json(ctx, data)

@cli.group()
def vuln() -> None:
    """Vulnerability operations."""

@vuln.command("get")
@click.argument("cve_id")
@click.option("--with-meta", is_flag=True, default=False, help="Include metadata.")
@click.option("--with-comments", is_flag=True, default=False, help="Include comments.")
@click.option("--with-linked", is_flag=True, default=False, help="Include linked vulns.")
@click.option("--with-bundles", is_flag=True, default=False, help="Include bundles.")
@click.option("--with-sightings", is_flag=True, default=False, help="Include sightings.")
@click.pass_context
@handle_errors
def vuln_get(ctx, cve_id, with_meta, with_comments, with_linked,
             with_bundles, with_sightings):
    """Get a specific vulnerability by ID."""
    data = get_client(ctx).vulnerability(
        cve_id,
        with_meta=_flag_or_none(with_meta),
        with_comments=_flag_or_none(with_comments),
        with_linked=_flag_or_none(with_linked),
        with_bundles=_flag_or_none(with_bundles),
        with_sightings=_flag_or_none(with_sightings),
    )
    output_json(ctx, data)

@vuln.command("list")
@click.option("--product", default=None, help="Filter by product.")
@click.option("--source", default=None, help="Filter by source.")
@click.option("--cwe", default=None, help="Filter by CWE ID.")
@click.option("--since", default=None, help="Only vulns since this date.")
@click.option("--sort-order", type=click.Choice(["asc", "desc"]),
              default=None, help="Sort order.")
@click.option("--date-sort", default=None, help="Date field to sort by.")
@pagination_options
@click.pass_context
@handle_errors
def vuln_list(ctx, product, source, cwe, since, sort_order, date_sort,
              page, per_page):
    """List vulnerabilities with optional filtering."""
    data = get_client(ctx).vulnerabilities(
        product=product, source=source, cwe=cwe, since=since,
        sort_order=sort_order, date_sort=date_sort,
        page=page, per_page=per_page,
    )
    output_json(ctx, data)

@vuln.command("search")
@click.argument("vendor")
@click.argument("product")
@click.option("--since", default=None, help="Only vulns since this date.")
@pagination_options
@click.pass_context
@handle_errors
def vuln_search(ctx, vendor, product, since, page, per_page):
    """Search vulnerabilities by vendor and product."""
    data = get_client(ctx).search(
        vendor, product, page=page, per_page=per_page, since=since,
    )
    output_json(ctx, data)

@vuln.command("cpe-search")
@click.argument("cpe")
@click.option("--source", default=None, help="Filter by source.")
@click.option("--sort-order", type=click.Choice(["asc", "desc"]),
              default=None, help="Sort order.")
@click.option("--date-sort", default=None, help="Date field to sort by.")
@pagination_options
@click.pass_context
@handle_errors
def vuln_cpe_search(ctx, cpe, source, sort_order, date_sort, page, per_page):
    """Search vulnerabilities by CPE string."""
    data = get_client(ctx).cpe_search(
        cpe, sort_order=sort_order, date_sort=date_sort,
        per_page=per_page, page=page, source=source,
    )
    output_json(ctx, data)

@vuln.command("vendors")
@click.pass_context
@handle_errors
def vuln_vendors(ctx):
    """List known vendors."""
    data = get_client(ctx).vendors()
    output_json(ctx, data)

@vuln.command("assigners")
@click.pass_context
@handle_errors
def vuln_assigners(ctx):
    """List known CNAs (Certificate Numbering Authorities)."""
    data = get_client(ctx).assigners()
    output_json(ctx, data)

@cli.group()
def cwe() -> None:
    """CWE operations."""

@cwe.command("get")
@click.argument("cwe_id")
@click.pass_context
@handle_errors
def cwe_get(ctx, cwe_id):
    """Get detailed CWE information."""
    data = get_client(ctx).cwe(cwe_id)
    output_json(ctx, data)

@cwe.command("list")
@click.option("--vuln-id", default=None, help="Filter by vulnerability ID.")
@pagination_options
@click.pass_context
@handle_errors
def cwe_list(ctx, vuln_id, page, per_page):
    """List all CWEs."""
    data = get_client(ctx).cwes(vuln_id=vuln_id, page=page, per_page=per_page)
    output_json(ctx, data)

@cli.group()
def capec() -> None:
    """CAPEC operations."""

@capec.command("get")
@click.argument("capec_id")
@click.pass_context
@handle_errors
def capec_get(ctx, capec_id):
    """Get detailed CAPEC information."""
    data = get_client(ctx).capec(capec_id)
    output_json(ctx, data)

@capec.command("list")
@pagination_options
@click.pass_context
@handle_errors
def capec_list(ctx, page, per_page):
    """List all CAPECs."""
    data = get_client(ctx).capecs(page=page, per_page=per_page)
    output_json(ctx, data)

@cli.group()
def kev() -> None:
    """KEV (Known Exploited Vulnerabilities) operations."""

@kev.command("list")
@click.option("--exploited", default=None, help="Filter by exploited status.")
@click.option("--status-reason", default=None, help="Filter by status reason.")
@click.option("--vuln-id", default=None, help="Filter by vulnerability ID.")
@click.option("--author", default=None, help="Filter by author.")
@click.option("--date-from", default=None, help="Start date filter.")
@click.option("--date-to", default=None, help="End date filter.")
@pagination_options
@click.pass_context
@handle_errors
def kev_list(ctx, exploited, status_reason, vuln_id, author,
             date_from, date_to, page, per_page):
    """List KEV entries."""
    data = get_client(ctx).kevs(
        exploited=exploited, status_reason=status_reason, vuln_id=vuln_id,
        author=author, date_from=date_from, date_to=date_to,
        page=page, per_page=per_page,
    )
    output_json(ctx, data)

@kev.command("get")
@click.argument("uuid")
@click.pass_context
@handle_errors
def kev_get(ctx, uuid):
    """Get a KEV entry by UUID."""
    data = get_client(ctx).kev(uuid)
    output_json(ctx, data)

@kev.command("cisa")
@pagination_options
@click.pass_context
@handle_errors
def kev_cisa(ctx, page, per_page):
    """List CISA Known Exploited Vulnerabilities."""
    data = get_client(ctx).cisa_kev(page=page, per_page=per_page)
    output_json(ctx, data)

@kev.command("cnw")
@pagination_options
@click.pass_context
@handle_errors
def kev_cnw(ctx, page, per_page):
    """List CNW KEV entries."""
    data = get_client(ctx).cnw_kev(page=page, per_page=per_page)
    output_json(ctx, data)

@cli.group()
def stats() -> None:
    """Statistics operations."""

@stats.command("vuln-count")
@click.option("--state", type=click.Choice(["published", "reserved"]),
              default=None, help="Vulnerability state.")
@click.option("--period", default=None, help="Time period (e.g. 2024-06).")
@click.option("--source", default=None, help="Data source.")
@click.pass_context
@handle_errors
def stats_vuln_count(ctx, state, period, source):
    """Get published/reserved vulnerability count."""
    data = get_client(ctx).stats_vulnerability_count(
        state=state, period=period, source=source,
    )
    output_json(ctx, data)

@stats.command("most-sighted")
@click.option("--sighting-type", default=None, help="Sighting type filter.")
@click.option("--limit", type=int, default=None, help="Max results.")
@click.option("--date-from", default=None, help="Start date.")
@click.option("--date-to", default=None, help="End date.")
@click.pass_context
@handle_errors
def stats_most_sighted(ctx, sighting_type, limit, date_from, date_to):
    """Get most sighted vulnerabilities."""
    data = get_client(ctx).stats_most_sighted(
        sighting_type=sighting_type, limit=limit,
        date_from=date_from, date_to=date_to,
    )
    output_json(ctx, data)

@stats.command("most-commented")
@click.option("--limit", type=int, default=None, help="Max results.")
@click.option("--date-from", default=None, help="Start date.")
@click.option("--date-to", default=None, help="End date.")
@click.pass_context
@handle_errors
def stats_most_commented(ctx, limit, date_from, date_to):
    """Get most commented vulnerabilities."""
    data = get_client(ctx).stats_most_commented(
        limit=limit, date_from=date_from, date_to=date_to,
    )
    output_json(ctx, data)

@stats.command("vendors-ranking")
@click.option("--limit", type=int, default=None, help="Max results.")
@click.option("--period", default=None, help="Time period.")
@click.option("--source", default=None, help="Data source.")
@click.pass_context
@handle_errors
def stats_vendors_ranking(ctx, limit, period, source):
    """Get vendors ranking."""
    data = get_client(ctx).stats_vendors_ranking(
        limit=limit, period=period, source=source,
    )
    output_json(ctx, data)

@stats.command("assigners-ranking")
@click.option("--limit", type=int, default=None, help="Max results.")
@click.option("--period", default=None, help="Time period.")
@click.option("--source", default=None, help="Data source.")
@click.pass_context
@handle_errors
def stats_assigners_ranking(ctx, limit, period, source):
    """Get assigners ranking."""
    data = get_client(ctx).stats_assigners_ranking(
        limit=limit, period=period, source=source,
    )
    output_json(ctx, data)

@stats.command("top-cwes")
@click.option("--limit", type=int, default=None, help="Max results.")
@click.option("--period", default=None, help="Time period.")
@click.pass_context
@handle_errors
def stats_top_cwes(ctx, limit, period):
    """Get most used CWEs based on sightings."""
    data = get_client(ctx).stats_most_used_cwes(limit=limit, period=period)
    output_json(ctx, data)

@cli.group()
def bundle() -> None:
    """Bundle operations."""

@bundle.command("get")
@click.argument("uuid")
@click.pass_context
@handle_errors
def bundle_get(ctx, uuid):
    """Get a bundle by UUID."""
    data = get_client(ctx).bundle(uuid)
    output_json(ctx, data)

@bundle.command("list")
@click.option("--vuln-id", default=None, help="Filter by vulnerability ID.")
@click.option("--author", default=None, help="Filter by author.")
@pagination_options
@click.pass_context
@handle_errors
def bundle_list(ctx, vuln_id, author, page, per_page):
    """List all bundles."""
    data = get_client(ctx).bundles(
        vuln_id=vuln_id, author=author, page=page, per_page=per_page,
    )
    output_json(ctx, data)

@cli.group()
def comment() -> None:
    """Comment operations."""

@comment.command("get")
@click.argument("uuid")
@click.pass_context
@handle_errors
def comment_get(ctx, uuid):
    """Get a specific comment."""
    data = get_client(ctx).comment(uuid)
    output_json(ctx, data)

@comment.command("list")
@click.option("--vuln-id", default=None, help="Filter by vulnerability ID.")
@click.option("--author", default=None, help="Filter by author.")
@pagination_options
@click.pass_context
@handle_errors
def comment_list(ctx, vuln_id, author, page, per_page):
    """List all comments."""
    data = get_client(ctx).comments(
        vuln_id=vuln_id, author=author, page=page, per_page=per_page,
    )
    output_json(ctx, data)

@cli.group()
def sighting() -> None:
    """Sighting operations."""

@sighting.command("get")
@click.argument("uuid")
@click.pass_context
@handle_errors
def sighting_get(ctx, uuid):
    """Get a specific sighting."""
    data = get_client(ctx).sighting(uuid)
    output_json(ctx, data)

@sighting.command("list")
@click.option("--type", "sighting_type", default=None, help="Sighting type.")
@click.option("--vuln-id", default=None, help="Filter by vulnerability ID.")
@click.option("--author", default=None, help="Filter by author.")
@pagination_options
@click.pass_context
@handle_errors
def sighting_list(ctx, sighting_type, vuln_id, author, page, per_page):
    """List all sightings."""
    data = get_client(ctx).sightings(
        type=sighting_type, vuln_id=vuln_id, author=author,
        page=page, per_page=per_page,
    )
    output_json(ctx, data)

@cli.group()
def emb3d() -> None:
    """MITRE EMB3D adversarial technique operations."""

@emb3d.command("get")
@click.argument("emb3d_id")
@click.pass_context
@handle_errors
def emb3d_get(ctx, emb3d_id):
    """Get detailed EMB3D technique information."""
    data = get_client(ctx).emb3d(emb3d_id)
    output_json(ctx, data)

@emb3d.command("list")
@click.option("--vuln-id", default=None, help="Filter by vulnerability ID.")
@pagination_options
@click.pass_context
@handle_errors
def emb3d_list(ctx, vuln_id, page, per_page):
    """List MITRE EMB3D adversarial techniques."""
    data = get_client(ctx).emb3d_techniques(
        vuln_id=vuln_id, page=page, per_page=per_page,
    )
    output_json(ctx, data)

@cli.group()
def gcve() -> None:
    """GCVE registry operations."""

@gcve.command("registry")
@click.option("--short-name", default=None, help="Filter by short name.")
@pagination_options
@click.pass_context
@handle_errors
def gcve_registry(ctx, short_name, page, per_page):
    """List GNAs from local GCVE registry."""
    data = get_client(ctx).gcve_registry(
        short_name=short_name, page=page, per_page=per_page,
    )
    output_json(ctx, data)

@gcve.command("integrity")
@click.pass_context
@handle_errors
def gcve_integrity(ctx):
    """Verify local GCVE registry integrity."""
    data = get_client(ctx).gcve_registry_integrity()
    output_json(ctx, data)

@cli.group()
def organization() -> None:
    """Organization operations."""

@organization.command("list")
@click.option("--name", default=None, help="Filter by name.")
@pagination_options
@click.pass_context
@handle_errors
def organization_list(ctx, name, page, per_page):
    """List all organizations."""
    data = get_client(ctx).organizations(name=name, page=page, per_page=per_page)
    output_json(ctx, data)

@cli.group()
def product() -> None:
    """Product operations."""

@product.command("list")
@click.option("--name", default=None, help="Filter by product name.")
@click.option("--organization-name", default=None, help="Filter by organization.")
@pagination_options
@click.pass_context
@handle_errors
def product_list(ctx, name, organization_name, page, per_page):
    """List all products."""
    data = get_client(ctx).products(
        name=name, organization_name=organization_name,
        page=page, per_page=per_page,
    )
    output_json(ctx, data)

@cli.command()
@click.argument("description")
@click.option("--model", default=None, help="ML model to use.")
@click.pass_context
@handle_errors
def classify(ctx, description, model):
    """Classify vulnerability severity from a description (VLAI)."""
    data = get_client(ctx).classify_severity(description, model=model)
    output_json(ctx, data)

@cli.group()
def system() -> None:
    """System information."""

@system.command("db-info")
@click.pass_context
@handle_errors
def system_db_info(ctx):
    """Get database information and update timestamps."""
    data = get_client(ctx).db_info()
    output_json(ctx, data)

@system.command("config")
@click.pass_context
@handle_errors
def system_config(ctx):
    """Get non-sensitive configuration information."""
    data = get_client(ctx).config_info()
    output_json(ctx, data)

@system.command("health")
@click.pass_context
@handle_errors
def system_health(ctx):
    """Check heartbeats of various processes."""
    data = get_client(ctx).check_process()
    output_json(ctx, data)

@system.command("pg-info")
@click.pass_context
@handle_errors
def system_pg_info(ctx):
    """Get PostgreSQL database information."""
    data = get_client(ctx).pg_info()
    output_json(ctx, data)

@system.command("smtp")
@click.pass_context
@handle_errors
def system_smtp(ctx):
    """Check SMTP connection."""
    data = get_client(ctx).check_smtp()
    output_json(ctx, data)

@system.command("valkey")
@click.pass_context
@handle_errors
def system_valkey(ctx):
    """Check if Valkey/Redis is operational."""
    data = get_client(ctx).valkey_up()
    output_json(ctx, data)

@cli.group()
def user() -> None:
    """User operations."""

@user.command("me")
@click.pass_context
@handle_errors
def user_me(ctx):
    """Get the currently authenticated user."""
    data = get_client(ctx).me()
    output_json(ctx, data)
