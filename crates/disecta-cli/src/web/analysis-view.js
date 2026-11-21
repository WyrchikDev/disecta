"use strict";

const confidenceLabels = {confirmed: "Confirmed", strong: "Strong candidate", heuristic: "Heuristic", unknown: "Unknown"};
const analysisState = {};
const flowView = createFlowView(byId("flow-canvas"), (block) => selectFlow(block), selectFlow, followFlowEdge);

function resetAnalysisView() {
  Object.assign(analysisState, {report: null, active: null, reference: null, call: null,
    graph: null, displayedGraph: null, block: null, instruction: null, rowCount: 0, callGraph: false});
  byId("function-search").value = "";
  byId("function-confidence").value = "";
  byId("function-sort").value = "address";
  byId("reference-address").value = "";
  byId("call-address").value = "";
  byId("flow-address").value = "";
}

function currentAddress() {
  return state.page?.instructions[state.selected]?.address
    ?? state.metadata.entry
    ?? state.metadata.sections.find((section) => section.execute && section.file_size)?.address;
}

function openAnalysisView(view, address) {
  if (view === "flow") {
    const start = address ?? analysisState.active ?? state.metadata.entry ?? currentAddress();
    if (start) openFlow(start);
    else {
      setAnalysisView("flow");
      message("This image has no file-backed executable entry.", true);
    }
    return;
  }
  const select = () => {
    if (view === "references") {
      analysisState.reference = address ?? analysisState.reference ?? currentAddress() ?? null;
      byId("reference-address").value = analysisState.reference ?? "";
    } else if (view === "calls") {
      analysisState.call = address ?? analysisState.active ?? analysisState.call;
      byId("call-address").value = analysisState.call ?? "";
    }
    setAnalysisView(view);
  };
  if (analysisState.report) {
    state.pending?.abort();
    message();
    select();
    return;
  }
  task(async (signal) => {
    const report = await analyze("/analysis", state.file, signal);
    if (signal.aborted) return;
    analysisState.report = report;
    select();
  });
}

function setAnalysisView(view) {
  state.view = view;
  state.recordsOffset = 0;
  render();
}

function openFlow(address) {
  if (analysisState.graph?.function.address === address) {
    state.pending?.abort();
    message();
    setAnalysisView("flow");
    return;
  }
  task(async (signal) => {
    const query = new URLSearchParams({function: address});
    const graph = await analyze("/cfg?" + query, state.file, signal);
    if (signal.aborted) return;
    Object.assign(analysisState, {graph, active: graph.function.address,
      block: graph.function.address, instruction: null});
    byId("flow-address").value = graph.function.address;
    setAnalysisView("flow");
  });
}

function parseAnalysisAddress(text) {
  const value = text.trim();
  if (!/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value) || BigInt(value) > 0xFFFFFFFFFFFFFFFFn) {
    message("Enter a 64-bit virtual address, for example 0x140001000.", true);
    return null;
  }
  message();
  return hex(value);
}

function renderAnalysisView() {
  if (state.view === "flow") {
    renderFlow();
    return;
  }
  const report = analysisState.report;
  let rows = [];
  if (state.view === "functions") {
    byId("function-limit").hidden = !report.limited;
    const search = byId("function-search").value.trim().toLowerCase();
    const confidence = byId("function-confidence").value;
    const sort = byId("function-sort").value;
    const candidates = report.functions.filter((entry) =>
      (!confidence || confidence === entry.confidence)
      && (entry.address.toLowerCase().includes(search) || entry.names.some((name) => name.toLowerCase().includes(search))));
    if (sort === "name") candidates.sort((a, b) => (a.names[0] ?? "\uffff").localeCompare(b.names[0] ?? "\uffff"));
    if (sort === "confidence") {
      const order = Object.keys(confidenceLabels);
      candidates.sort((a, b) => order.indexOf(a.confidence) - order.indexOf(b.confidence));
    }
    columns(["Entry", "Name", "Confidence", "Instructions"]);
    renderAnalysisRows(candidates, (entry) => tableRow([
      addressButton(entry.address, () => openFlow(entry.address)), entry.names.join(", ") || "—",
      confidenceLabels[entry.confidence] + (entry.overlaps ? " / overlap" : ""), entry.instructions,
    ]), "No matching functions.");
    showAnalysisDetails("Function analysis", [
      ["Candidates", report.functions.length],
      ["References", report.references.length],
      ["Analysis", report.limited ? "Partial" : "Finished"],
    ]);
  } else if (state.view === "calls") {
    byId("call-limit").hidden = !report.limited;
    const address = analysisState.call;
    rows = report.references.filter((ref) => (ref.kind === "call" || ref.kind === "indirect_call")
      && (!address || ref.function === address || ref.target === address));
    columns(["Caller", "Call site", "Callee", "Relationship"]);
    renderAnalysisRows(rows, (ref) => tableRow([
      addressButton(ref.function, () => openFlow(ref.function)),
      addressButton(ref.source, () => jump(ref.source)),
      ref.target ? addressButton(ref.target, () => navigateCode(ref.target, true)) : "Unresolved",
      ref.kind === "call" ? "Direct" : "Indirect",
    ]), "No matching call sites.");
    const counts = [["Call sites", rows.length], ["Unresolved", rows.filter((ref) => !ref.target).length]];
    if (address) counts.unshift(["Function", address], ["Incoming", rows.filter((ref) => ref.target === address).length],
      ["Outgoing", rows.filter((ref) => ref.function === address).length]);
    showAnalysisDetails("Calls", counts, address ? [detailAction("Control flow", () => openFlow(address))] : []);
    const graphMode = analysisState.callGraph && Boolean(address);
    const toggle = byId("call-graph-mode");
    toggle.disabled = !address;
    toggle.setAttribute("aria-pressed", String(graphMode));
    if (graphMode) {
      renderCallGraph(report, address, rows);
      byId("pager").hidden = true;
      return;
    }
  } else {
    byId("reference-limit").hidden = !report.limited;
    const address = analysisState.reference;
    for (const ref of report.references) {
      if (ref.target === address && address) rows.push({ref, direction: "Incoming"});
      if (ref.source === address) rows.push({ref, direction: "Outgoing"});
    }
    columns(["Direction", "Source", "Target", "Kind"]);
    renderAnalysisRows(rows, ({ref, direction}) => tableRow([
      direction, addressButton(ref.source, () => jump(ref.source)),
      ref.target ? addressButton(ref.target, () => navigateCode(ref.target)) : "Unresolved",
      referenceType(ref, report),
    ]), "No recovered references for this address.");
    showAnalysisDetails("References", [
      ["Address", address ?? "—"],
      ["Incoming", rows.filter((row) => row.direction === "Incoming").length],
      ["Outgoing", rows.filter((row) => row.direction === "Outgoing").length],
    ]);
  }
  renderPager();
}

function renderCallGraph(report, address, rows) {
  const graph = byId("call-graph");
  graph.hidden = false;
  byId("table-scroll").hidden = true;
  const byEntry = new Map(report.functions.map((entry) => [entry.address, entry]));
  const callers = new Map();
  const callees = new Map();
  for (const ref of rows) {
    if (ref.target === address) callers.set(ref.function, (callers.get(ref.function) ?? 0) + 1);
    if (ref.function === address) callees.set(ref.target, (callees.get(ref.target) ?? 0) + 1);
  }
  const column = (label, neighbors) => {
    const section = element("section");
    section.append(element("h2", label));
    if (!neighbors.size) section.append(element("p", "No recovered call sites"));
    for (const [target, count] of Array.from(neighbors).slice(0, 100)) {
      const entry = byEntry.get(target);
      const title = entry?.names[0] ?? target ?? "Unresolved indirect calls";
      const node = element(target ? "button" : "div", undefined, "call-node");
      node.append(element("strong", title), element("span", count + (count === 1 ? " call site" : " call sites")));
      if (target) {
        node.type = "button";
        node.title = target;
        node.addEventListener("click", () => openAnalysisView("calls", target));
      }
      section.append(node);
    }
    if (neighbors.size > 100) section.append(element("p", "See the call table for all sites."));
    return section;
  };
  const current = element("section");
  current.append(element("h2", "Selected function"));
  const center = element("div", undefined, "call-node focus");
  const name = byEntry.get(address)?.names[0];
  if (name) center.append(element("strong", name));
  center.append(element("code", address), detailAction("Open CFG", () => openFlow(address)));
  current.append(center);
  graph.replaceChildren(column("Callers", callers), current, column("Callees", callees));
}

function referenceType(ref, report) {
  const slot = report.import_slots[ref.target];
  const label = ref.kind === "ip_relative" ? "IP-relative" : ref.kind.replaceAll("_", " ");
  return slot ? label + " / " + (slot.library ? slot.library + "!" : "") + slot.name :
    ref.target_kind ? label + " / " + ref.target_kind.replaceAll("_", " ") : label;
}

function renderAnalysisRows(records, renderRow, empty) {
  analysisState.rowCount = records.length;
  emptyTable(records.length ? "" : empty);
  byId("rows").replaceChildren(...records
    .slice(state.recordsOffset, state.recordsOffset + recordPageSize).map(renderRow));
}

function tableRow(values) {
  const row = element("tr");
  for (const value of values) {
    const cell = element("td");
    cell.append(value instanceof Node ? value : String(value));
    row.append(cell);
  }
  return row;
}

function addressButton(address, action) {
  const button = element("button", address, "table-action");
  button.type = "button";
  button.addEventListener("click", action);
  return button;
}

function detailAction(label, action) {
  const button = element("button", label);
  button.type = "button";
  button.addEventListener("click", action);
  return button;
}

function showAnalysisDetails(heading, properties, actions = []) {
  byId("details-heading").textContent = heading;
  const info = element("dl");
  for (const [name, value] of properties) info.append(element("dt", name), element("dd", value));
  const controls = element("div", undefined, "detail-actions");
  controls.append(...actions);
  byId("details").replaceChildren(info, controls);
}

function navigateCode(address, cfg = false) {
  if (sectionsAt(BigInt(address)).length) {
    if (cfg) openFlow(address);
    else jump(address);
    return;
  }
  const virtual = BigInt(address);
  const dataSection = state.metadata.sections.findIndex((section) => {
    const offset = virtual - BigInt(section.address);
    return offset >= 0n && offset < BigInt(section.size);
  });
  if (dataSection < 0) {
    message("Target " + address + " is outside the mapped image.", true);
  } else {
    showSection(dataSection);
    byId("address").value = address;
    byId("details").append(element("h3", "Referenced address"), element("code", address),
      detailAction("References", () => openAnalysisView("references", address)));
  }
}

function followFlowEdge(edge) {
  if (edge.block) {
    const block = analysisState.graph.blocks.find((candidate) => candidate.start === edge.block);
    if (block) selectFlow(block);
    return;
  }
  if (edge.target) navigateCode(edge.target, edge.kind === "call");
}

function selectFlow(block, instruction = null) {
  analysisState.block = block.start;
  analysisState.instruction = instruction ?? null;
  flowView.select(block.start, instruction?.address);
  renderFlowDetails();
}

function renderFlow() {
  const graph = analysisState.graph;
  byId("pager").hidden = true;
  byId("flow-save").disabled = !graph;
  byId("flow-canvas").hidden = !graph?.blocks.length;
  for (const id of ["flow-fit", "flow-zoom-in", "flow-zoom-out"]) {
    byId(id).disabled = !graph?.blocks.length;
  }
  if (graph && analysisState.displayedGraph !== graph) {
    flowView.render(graph);
    analysisState.displayedGraph = graph;
  }
  const status = [];
  if (graph?.entry_status) status.push("Entry: " + graph.entry_status.replaceAll("_", " ") + ".");
  if (graph?.function.limited) status.push("Partial graph. Analysis budget reached.");
  if (!graph) status.push("Enter an executable virtual address.");
  const label = byId("flow-status");
  label.hidden = !status.length;
  label.textContent = status.join(" ");
  if (!graph) {
    showAnalysisDetails("Control flow", []);
    return;
  }
  flowView.select(analysisState.block, analysisState.instruction?.address);
  renderFlowDetails();
}

function evidenceText(item) {
  switch (item.kind) {
    case "symbol": return "Code symbol: " + item.name;
    case "export": return "Export: " + item.name;
    case "entry_point": return "Executable entry point";
    case "runtime_range": return "PE runtime range through " + item.end;
    case "direct_call": return "Direct call at " + item.site;
    case "requested": return "Selected address";
  }
}

function renderFlowDetails() {
  const graph = analysisState.graph;
  const known = analysisState.report?.functions.find((entry) => entry.address === graph.function.address);
  const entry = known ?? graph.function;
  const block = graph.blocks.find((candidate) => candidate.start === analysisState.block);
  const instruction = analysisState.instruction;
  const location = instruction?.address ?? block?.start ?? entry.address;
  const properties = [
    ["Entry", entry.address],
    ["Confidence", confidenceLabels[entry.confidence]],
    ["Blocks", graph.blocks.length],
  ];
  if (entry.names.length) properties.unshift(["Function", entry.names.join(", ")]);
  if (entry.declared_end) properties.push(["Declared end", entry.declared_end]);
  if (entry.overlaps || entry.conflicting_extent) properties.push(["Bounds", "Ambiguous"]);
  if (block) properties.push(["Block", block.start]);
  if (instruction) properties.push(["Instruction", instruction.text]);
  showAnalysisDetails("Control flow", properties, [
    detailAction("Show assembly", () => jump(location)),
    detailAction("References", () => openAnalysisView("references", location)),
    detailAction("Calls", () => openAnalysisView("calls", entry.address)),
  ]);
  const details = byId("details");
  if (block) {
    const transfers = graph.edges.filter((edge) => edge.from === block.start);
    if (transfers.length) {
      details.append(element("h3", "Transfers"));
      const list = element("ul", undefined, "flow-details");
      for (const edge of transfers) {
        const kind = edge.kind.replaceAll("_", " ");
        const item = element("li", edge.target ? kind + " → " : kind + " / " + edge.resolution.replaceAll("_", " "));
        if (edge.target) {
          item.append(addressButton(edge.target, () => followFlowEdge(edge)));
          if (!edge.block) item.append(" (" + edge.resolution.replaceAll("_", " ") + ")");
        }
        list.append(item);
      }
      details.append(list);
    }
    details.append(element("h3", "Block instructions"));
    const list = element("ul", undefined, "flow-details");
    for (const row of block.instructions) {
      const item = element("li");
      const button = addressButton(row.address + " " + row.text, () => selectFlow(block, row));
      button.setAttribute("aria-pressed", String(row.address === instruction?.address));
      item.append(button);
      list.append(item);
    }
    details.append(list);
  }
  if (entry.evidence.length) {
    details.append(element("h3", "Entry evidence"));
    const list = element("ul", undefined, "flow-details");
    for (const item of entry.evidence.slice(0, 20)) list.append(element("li", evidenceText(item)));
    if (entry.evidence.length > 20) list.append(element("li", (entry.evidence.length - 20) + " more in JSON"));
    details.append(list);
  }
  if (graph.unrecovered_ranges.length) {
    details.append(element("h3", "Unrecovered ranges"));
    const list = element("ul", undefined, "flow-details");
    for (const range of graph.unrecovered_ranges.slice(0, 20)) {
      list.append(element("li", range.start + "–" + range.end));
    }
    if (graph.unrecovered_ranges.length > 20) list.append(element("li", "See JSON for all ranges"));
    details.append(list);
  }
}

byId("function-search").addEventListener("input", () => setAnalysisView("functions"));
for (const id of ["function-confidence", "function-sort"]) {
  byId(id).addEventListener("change", () => setAnalysisView("functions"));
}
byId("reference-tools").addEventListener("submit", (event) => {
  event.preventDefault();
  const address = parseAnalysisAddress(byId("reference-address").value);
  if (address) openAnalysisView("references", address);
});
byId("call-filter").addEventListener("submit", (event) => {
  event.preventDefault();
  const address = parseAnalysisAddress(byId("call-address").value);
  if (address) openAnalysisView("calls", address);
});
byId("call-all").addEventListener("click", () => {
  analysisState.call = null;
  byId("call-address").value = "";
  setAnalysisView("calls");
});
byId("call-graph-mode").addEventListener("click", () => {
  analysisState.callGraph = !analysisState.callGraph;
  setAnalysisView("calls");
});
byId("flow-function").addEventListener("submit", (event) => {
  event.preventDefault();
  const start = parseAnalysisAddress(byId("flow-address").value);
  if (start) openFlow(start);
});
byId("flow-fit").addEventListener("click", flowView.fit);
byId("flow-zoom-out").addEventListener("click", () => flowView.zoom(1.2));
byId("flow-zoom-in").addEventListener("click", () => flowView.zoom(1 / 1.2));
byId("flow-save").addEventListener("click", () => {
  const graph = analysisState.graph;
  downloadJson("cfg-" + graph.function.address + ".json", graph);
});
