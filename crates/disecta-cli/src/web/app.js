"use strict";

const byId = (id) => document.getElementById(id);
const viewNames = {disassembly: "Disassembly", symbols: "Symbols", imports: "Imports", exports: "Exports"};
const recordPageSize = 256;
const state = {
  file: null, metadata: null, section: null, page: null, view: "disassembly",
  selected: 0, history: [], recordsOffset: 0, pending: null,
};

function element(tag, value, className) {
  const node = document.createElement(tag);
  if (value !== undefined) node.textContent = value;
  if (className) node.className = className;
  return node;
}

function message(text = "", error = false) {
  const status = byId("message");
  status.hidden = !text;
  status.textContent = text;
  status.classList.toggle("error", error);
}

async function task(action) {
  state.pending?.abort();
  const pending = new AbortController();
  state.pending = pending;
  message("Reading binary…");
  try {
    await action(pending.signal);
    if (!pending.signal.aborted) message();
  } catch (error) {
    if (!pending.signal.aborted) message(error.message, true);
  } finally {
    if (state.pending === pending) state.pending = null;
  }
}

async function analyze(path, file, signal) {
  const response = await fetch(path, {
    method: "POST",
    headers: {"Content-Type": "application/octet-stream", "X-Disecta": "1"},
    body: file,
    signal,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error);
  return data;
}

function open(loader) {
  task(async (signal) => {
    const file = await loader(signal);
    const {metadata, page} = await analyze("/open", file, signal);
    if (signal.aborted) return;
    Object.assign(state, {
      file, metadata, page, section: page?.section ?? null, view: "disassembly",
      selected: 0, history: [], recordsOffset: 0,
    });
    byId("filename").textContent = file.name;
    byId("filetype").textContent = metadata.format + " / " + metadata.architecture;
    byId("entry").hidden = !metadata.entry;
    byId("empty").hidden = true;
    byId("save").hidden = false;
    byId("workbench").hidden = false;
    render();
  });
}

function permissions(section) {
  return (section.read === null ? "?" : section.read ? "r" : "-")
    + (section.write ? "w" : "-") + (section.execute ? "x" : "-");
}

function renderSections() {
  const nav = byId("sections");
  // Reuse buttons when a page changes so keyboard focus stays in the navigator.
  if (nav.metadata !== state.metadata) {
    nav.metadata = state.metadata;
    nav.replaceChildren(...state.metadata.sections.map((section, index) => {
      const button = element("button", undefined, "section");
      button.type = "button";
      button.title = section.address + " / " + permissions(section);
      button.append(element("span", section.name || "(unnamed)"), element("span", permissions(section)));
      button.addEventListener("click", () => showSection(index));
      return button;
    }));
  }
  for (const [index, button] of Array.from(nav.children).entries()) {
    button.setAttribute("aria-current", String(index === state.section));
  }
}

function showSection(index) {
  const section = state.metadata.sections[index];
  if (section.execute && section.file_size > 0 && section.size > 0) {
    showPage(index);
    return;
  }
  state.pending?.abort();
  message();
  Object.assign(state, {section: index, page: null, selected: 0, history: [], view: "disassembly"});
  render();
}

function showPage(section, start, history = []) {
  const parameters = new URLSearchParams({section});
  if (start) parameters.set("start", start);
  task(async (signal) => {
    const page = await analyze("/disasm?" + parameters, state.file, signal);
    if (signal.aborted) return;
    Object.assign(state, {page, section, selected: 0, history, view: "disassembly"});
    render();
  });
}

function hex(value) {
  return "0x" + BigInt(value).toString(16).toUpperCase();
}

function jump(value) {
  if (!/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value)) {
    message("Enter a virtual address, for example 0x140001000.", true);
    return;
  }
  const address = BigInt(value);
  const sections = sectionsAt(address);
  if (sections.length !== 1) {
    const text = sections.length ? "Several sections cover that address. Select a section first." :
      "That address is outside file-backed executable code.";
    if (sections.includes(state.section)) {
      showPage(state.section, hex(address));
    } else {
      message(text, true);
    }
    return;
  }
  const visible = state.page?.instructions.findIndex((row) => BigInt(row.address) === address) ?? -1;
  if (visible >= 0 && state.section === sections[0]) {
    state.pending?.abort();
    message();
    state.view = "disassembly";
    state.selected = visible;
    render();
    byId("rows").children[visible].focus();
  } else {
    showPage(sections[0], hex(address));
  }
}

function sectionsAt(address) {
  return state.metadata.sections.flatMap((section, index) => {
    const begin = BigInt(section.address);
    const size = section.file_size < section.size ? section.file_size : section.size;
    return section.execute && address >= begin && address < begin + BigInt(size) ? [index] : [];
  });
}

function render() {
  renderSections();
  for (const button of document.querySelectorAll("[data-view]")) {
    button.setAttribute("aria-pressed", String(button.dataset.view === state.view));
  }
  byId("table").setAttribute("aria-label", viewNames[state.view]);
  byId("table-scroll").scrollTop = 0;
  if (state.view === "disassembly") renderDisassembly();
  else renderRecords();
  renderDetails();
  renderPager();
}

function columns(names) {
  const row = element("tr");
  for (const name of names) {
    const heading = element("th", name);
    heading.scope = "col";
    row.append(heading);
  }
  byId("columns").replaceChildren(row);
}

function emptyTable(text) {
  byId("table").hidden = Boolean(text);
  byId("empty-view").hidden = !text;
  byId("empty-view").textContent = text;
}

function renderDisassembly() {
  columns(["Address", "Bytes", "Instruction"]);
  const instructions = state.page?.instructions ?? [];
  emptyTable(instructions.length ? "" : "This view has no file-backed instructions.");
  byId("rows").replaceChildren(...instructions.map((instruction, index) => {
    const row = element("tr");
    row.dataset.index = index;
    row.tabIndex = index === state.selected ? 0 : -1;
    row.setAttribute("aria-selected", String(index === state.selected));
    const code = element("td", undefined, instruction.invalid ? "invalid" : "");
    if (instruction.invalid) {
      code.textContent = "Invalid instruction";
    } else {
      const space = instruction.text.indexOf(" ");
      const mnemonic = space < 0 ? instruction.text : instruction.text.slice(0, space);
      const operands = space < 0 ? "" : instruction.text.slice(space + 1);
      code.append(element("span", mnemonic, "mnemonic"), element("span", operands, instruction.target ? "branch" : ""));
    }
    row.append(element("td", instruction.address, "addr"), element("td", instruction.bytes, "bytes"), code);
    return row;
  }));
}

function renderRecords() {
  const records = state.metadata[state.view];
  const imports = state.view === "imports";
  const symbols = state.view === "symbols";
  columns(imports ? ["Library", "Name"] : symbols ? ["Address", "Name", "Kind"] : ["Address", "Name", "Target"]);
  emptyTable(records.length ? "" : "No " + state.view + " recorded in this image.");
  byId("rows").replaceChildren(...records.slice(state.recordsOffset, state.recordsOffset + recordPageSize).map((record) => {
    const row = element("tr");
    const location = element("td", (imports ? record.library : record.address) || "—", "addr");
    if (record.address && sectionsAt(BigInt(record.address)).length === 1) {
      const link = element("button", record.address, "table-action");
      link.type = "button";
      link.addEventListener("click", () => jump(record.address));
      location.replaceChildren(link);
    }
    row.append(location, element("td", record.name));
    if (symbols) row.append(element("td", record.kind));
    else if (!imports) row.append(element("td", record.target_detail ?? "—"));
    return row;
  }));
}

function renderDetails() {
  const instruction = state.view === "disassembly" ? state.page?.instructions[state.selected] : null;
  const section = state.metadata.sections[state.section];
  const detail = byId("details");
  byId("details-heading").textContent = instruction ? "Instruction" : "Image";
  detail.replaceChildren();
  const data = instruction ? [
    ["Address", instruction.address], ["File offset", hex(instruction.file_offset)],
    ["Length", instruction.length + (instruction.length === 1 ? " byte" : " bytes")],
    ["Flow", instruction.flow.replace(/([a-z])([A-Z])/g, "$1 $2")],
    ["Opcode", instruction.opcode],
  ] : [
    ["Image base", state.metadata.image_base], ["Entry point", state.metadata.entry ?? "—"],
    ["File size", state.metadata.file_size.toLocaleString() + " bytes"],
  ];
  if (instruction) detail.append(element("pre", instruction.invalid ? "Invalid instruction" : instruction.text));
  if (!instruction && section) {
    data.push(["Section", section.name], ["Address", section.address],
      ["File offset", section.file_offset === null ? "—" : hex(section.file_offset)],
      ["Virtual size", hex(section.size)], ["Permissions", permissions(section)]);
  }
  const list = element("dl");
  for (const [name, value] of data) list.append(element("dt", name), element("dd", value));
  detail.append(list);
  if (instruction?.operands.length) {
    detail.append(element("h3", "Operands"));
    const operands = element("ol");
    for (const operand of instruction.operands) {
      operands.append(element("li", describeOperand(operand)));
    }
    detail.append(operands);
  }
  if (instruction?.target && sectionsAt(BigInt(instruction.target)).length) {
    const target = element("button", "Go to target");
    target.type = "button";
    target.addEventListener("click", () => jump(instruction.target));
    detail.append(target);
  }
}

function describeOperand(operand) {
  switch (operand.kind) {
    case "register": return operand.name + " (register)";
    case "immediate": return operand.value + " (immediate)";
    case "near_branch": return operand.target + " (target)";
    case "far_branch": return hex(operand.selector) + ":" + operand.offset;
    case "memory": {
      const terms = [operand.base, operand.index && operand.index + " × " + operand.scale];
      if (operand.displacement !== "0x0" || !terms.some(Boolean)) terms.push(operand.displacement);
      const address = operand.resolved_address ? " → " + operand.resolved_address : "";
      return operand.segment + ":[" + terms.filter(Boolean).join(" + ") + "]" + address
        + (operand.width ? " (" + operand.width + " B)" : "");
    }
  }
}

function renderPager() {
  const disassembly = state.view === "disassembly";
  const rows = state.page?.instructions ?? [];
  const pager = byId("pager");
  if (disassembly) {
    pager.hidden = !rows.length;
    if (!rows.length) return;
    byId("previous").disabled = !state.history.length;
    byId("next").disabled = !state.page.next_address;
    byId("page-range").textContent = rows[0].address + " – " + rows.at(-1).address;
  } else {
    const length = state.metadata[state.view].length;
    pager.hidden = length <= recordPageSize;
    byId("previous").disabled = !state.recordsOffset;
    byId("next").disabled = state.recordsOffset + recordPageSize >= length;
    byId("page-range").textContent = (state.recordsOffset + 1) + "–"
      + Math.min(state.recordsOffset + recordPageSize, length) + " of " + length;
  }
}

function movePage(direction) {
  if (state.view !== "disassembly") {
    state.recordsOffset += direction * recordPageSize;
    render();
    return;
  }
  const start = direction < 0 ? state.history.at(-1) : state.page.next_address;
  const history = direction < 0 ? state.history.slice(0, -1) :
    [...state.history, state.page.instructions[0].address];
  showPage(state.section, start, history);
}

function selectRow(index) {
  const rows = byId("rows").children;
  const next = rows[index];
  if (!next) return;
  const previous = rows[state.selected];
  previous.tabIndex = -1;
  previous.setAttribute("aria-selected", "false");
  state.selected = index;
  next.tabIndex = 0;
  next.setAttribute("aria-selected", "true");
  next.focus();
  renderDetails();
}

byId("open").addEventListener("click", () => byId("upload").click());
byId("upload").addEventListener("change", (event) => {
  const file = event.target.files[0];
  if (file) open(async () => file);
  event.target.value = "";
});
byId("example").addEventListener("click", () => open(async (signal) => {
  const result = await fetch("/example", {signal});
  if (!result.ok) throw new Error("Could not load the example.");
  return new File([await result.blob()], "branch.exe", {type: "application/octet-stream"});
}));
byId("entry").addEventListener("click", () => jump(state.metadata.entry));
byId("jump").addEventListener("submit", (event) => {
  event.preventDefault();
  jump(byId("address").value.trim());
});
byId("previous").addEventListener("click", () => movePage(-1));
byId("next").addEventListener("click", () => movePage(1));
byId("rows").addEventListener("click", (event) => {
  const row = event.target.closest("tr[data-index]");
  if (row) selectRow(Number(row.dataset.index));
});
byId("rows").addEventListener("keydown", (event) => {
  if (state.view !== "disassembly" || !["ArrowUp", "ArrowDown"].includes(event.key)) return;
  event.preventDefault();
  selectRow(state.selected + (event.key === "ArrowUp" ? -1 : 1));
});
for (const button of document.querySelectorAll("[data-view]")) {
  button.addEventListener("click", () => {
    state.view = button.dataset.view;
    state.recordsOffset = 0;
    render();
  });
}
byId("save").addEventListener("click", () => {
  const data = JSON.stringify({file: state.file.name, metadata: state.metadata, page: state.page}, null, 2);
  const url = URL.createObjectURL(new Blob([data], {type: "application/json"}));
  const link = element("a");
  link.href = url;
  link.download = state.file.name + ".json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
document.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "o") {
    event.preventDefault();
    byId("upload").click();
  } else if (event.key === "g" && !event.ctrlKey && !event.metaKey && !event.altKey
      && state.metadata && !event.target.matches("input, textarea, [contenteditable]")) {
    event.preventDefault();
    byId("address").focus();
  }
});
