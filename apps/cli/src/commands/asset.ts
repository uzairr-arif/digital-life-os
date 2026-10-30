import type { Command } from "commander";
import { normalizeDomain, newId } from "@dlos/core";
import { renderAssetsTable } from "@dlos/reports";
import { fail, ctxFrom, note } from "../ui";

export function registerAssetCommands(program: Command): void {
  const asset = program.command("asset").description("Manage the asset inventory");

  asset
    .command("add <identifier>")
    .description("Add a domain you own or are authorized to assess (passive checks only)")
    .option("--type <type>", "asset type (only 'domain' is supported today)", "domain")
    .option("--label <label>", "human-friendly label")
    .option("--group <group>", 'group name, e.g. "personal" or "work"')
    .option(
      "--dkim-selector <selector>",
      "DKIM selector to check (repeatable; DKIM is only checked for known selectors)",
      (v: string, prev: string[]) => [...prev, v],
      [] as string[],
    )
    .option("--confirm", "confirm you own this asset or are authorized to assess it (required)")
    .action((identifier: string, opts, cmd) => {
      if (opts.type !== "domain") {
        return fail(`unsupported asset type "${opts.type}" (only "domain" is supported today)`);
      }
      if (!opts.confirm) {
        return fail(
          "you must confirm scope: re-run with --confirm to attest that you own this domain or are authorized to assess it. Digital Life OS only performs passive checks on assets you confirm.",
        );
      }
      let domain: string;
      try {
        domain = normalizeDomain(identifier);
      } catch (err) {
        return fail(err instanceof Error ? err.message : String(err));
      }

      const { storage, dbPath } = ctxFrom(cmd);
      if (storage.getAssetByIdentifier(domain)) {
        return fail(`${domain} is already in the inventory`);
      }

      const now = new Date().toISOString();
      storage.insertAsset({
        id: newId(),
        type: "domain",
        identifier: domain,
        label: opts.label,
        group: opts.group,
        ownershipConfirmedAt: now,
        dkimSelectors: opts.dkimSelector ?? [],
        createdAt: now,
        active: true,
      });
      console.log(`✔ added ${domain}`);
      console.log(`  scope confirmed at ${now} (passive checks only)`);
      if (opts.dkimSelector?.length) {
        console.log(`  dkim selectors: ${opts.dkimSelector.join(", ")}`);
      }
      note(`  database: ${dbPath}`);
      note(`  next: dlos scan ${domain}`);
    });

  asset.command("list").description("List tracked assets").action((_opts, cmd) => {
    const { storage } = ctxFrom(cmd);
    const assets = storage.listAssets();
    const open = storage.listFindings({ statuses: ["open", "in_progress"] });
    const counts = new Map<string, number>();
    for (const f of open) counts.set(f.assetId, (counts.get(f.assetId) ?? 0) + 1);
    console.log(renderAssetsTable(assets, counts));
  });

  asset
    .command("show <identifier>")
    .description("Show details for one asset")
    .action((identifier: string, _opts, cmd) => {
      const { storage } = ctxFrom(cmd);
      const found = storage.getAssetByIdentifier(identifier.toLowerCase().trim());
      if (!found) return fail(`unknown asset "${identifier}"`);
      const open = storage.listFindings({ assetId: found.id, statuses: ["open", "in_progress"] });
      const scans = storage.listScans(found.id, 5);
      console.log(`identifier:            ${found.identifier}`);
      console.log(`type:                  ${found.type}`);
      if (found.label) console.log(`label:                 ${found.label}`);
      if (found.group) console.log(`group:                 ${found.group}`);
      console.log(`scope confirmed:       ${found.ownershipConfirmedAt ?? "NO"}`);
      console.log(`dkim selectors:        ${found.dkimSelectors.join(", ") || "(none)"}`);
      console.log(`created:               ${found.createdAt}`);
      console.log(`last checked:          ${found.lastCheckedAt ?? "never"}`);
      console.log(`open findings:         ${open.length}`);
      console.log(`recent scans:          ${scans.length}`);
      note("next: dlos scan <domain> · dlos history <domain> · dlos report <domain>");
    });

  asset
    .command("remove <identifier>")
    .description("Remove an asset and all of its stored history")
    .action((identifier: string, _opts, cmd) => {
      const { storage } = ctxFrom(cmd);
      const found = storage.getAssetByIdentifier(identifier.toLowerCase().trim());
      if (!found) return fail(`unknown asset "${identifier}"`);
      storage.deleteAssetDeep(found.id);
      console.log(`✔ removed ${found.identifier} (including scans, observations and findings)`);
    });
}
