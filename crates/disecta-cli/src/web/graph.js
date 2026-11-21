"use strict";

function createFlowView(svg, onBlock, onInstruction, onTarget) {
  const ns = "http://www.w3.org/2000/svg";
  const width = 326;
  const height = 132;
  const lane = 84;
  const margin = 42;
  let full = [0, 0, 640, 440];
  let view = [...full];
  let drag = null;
  let moved = false;
  let nodes = new Map();
  let lines = new Map();

  function shape(tag, attrs, text) {
    const node = document.createElementNS(ns, tag);
    for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function layout(graph) {
    // Shortest forward distances from entry give stable ranks even in cyclic graphs.
    // Place a branch's fallthrough first and preserve discovery order within a rank.
    const successors = new Map();
    for (const edge of graph.edges) {
      if (!successors.has(edge.from)) successors.set(edge.from, []);
      successors.get(edge.from).push(edge);
    }
    const byStart = new Map(graph.blocks.map((block) => [block.start, block]));
    const discovered = new Map([[graph.function.address, 0]]);
    const queue = [graph.function.address];
    const rows = [];
    for (let cursor = 0; cursor < queue.length; cursor++) {
      const start = queue[cursor];
      const rank = discovered.get(start);
      (rows[rank] ??= []).push(byStart.get(start));
      const edges = successors.get(start) ?? [];
      for (const edge of [...edges].sort((a, b) => Number(b.kind === "fallthrough") - Number(a.kind === "fallthrough"))) {
        if (edge.block && !discovered.has(edge.block)) {
          discovered.set(edge.block, rank + 1);
          queue.push(edge.block);
        }
      }
    }
    const rowWidth = rows.reduce((largest, row) => Math.max(largest, row.length), 1);
    const totalWidth = rowWidth * (width + lane) - lane;
    const result = new Map();
    for (const [rank, row] of rows.entries()) {
      const inset = (totalWidth - (row.length * (width + lane) - lane)) / 2;
      for (const [column, block] of row.entries()) {
        result.set(block.start, {
          x: margin + inset + column * (width + lane),
          y: margin + rank * (height + lane),
          boxHeight: 41 + Math.min(4, block.instructions.length) * 19,
          rank,
          block,
        });
      }
    }
    return {positions: result, totalWidth, height: rows.length * (height + lane)};
  }

  function render(graph) {
    svg.replaceChildren();
    nodes = new Map();
    lines = new Map();
    if (!graph.blocks.length) return;
    const grid = layout(graph);
    const defs = shape("defs", {});
    for (const kind of ["branch_taken", "fallthrough", "jump", "external"]) {
      const pointer = shape("marker", {id: "flow-arrow-" + kind, viewBox: "0 0 10 10", markerWidth: 6,
        markerHeight: 6, refX: 9, refY: 5, orient: "auto-start-reverse", class: kind});
      pointer.append(shape("path", {d: "M 0 0 L 10 5 L 0 10 z"}));
      defs.append(pointer);
    }
    const edges = shape("g", {class: "flow-edges"});
    const blocks = shape("g", {});
    svg.append(defs, edges, blocks);
    let minX = 0;
    let maxX = grid.totalWidth + margin * 2;
    let maxY = grid.height + margin;
    const externalLanes = new Map();
    for (const edge of graph.edges) {
      const source = grid.positions.get(edge.from);
      const destination = grid.positions.get(edge.block);
      const outgoing = externalLanes.get(edge.from) ?? 0;
      const x1 = source.x + width * (edge.kind === "branch_taken" ? .72 : .42);
      const y1 = source.y + source.boxHeight;
      let d;
      if (destination?.rank === source.rank + 1) {
        const x2 = destination.x + width / 2;
        const y2 = destination.y;
        const midY = (y1 + y2) / 2;
        d = ["M", x1, y1, "C", x1, midY, x2, midY, x2, y2].join(" ");
      } else if (destination && destination.rank === source.rank
          && Math.abs(destination.x - source.x) === width + lane) {
        const right = destination.x > source.x;
        d = ["M", source.x + (right ? width : 0), source.y + 23, "H", destination.x + (right ? 0 : width)].join(" ");
      } else if (destination) {
        // Route non-local edges through row gaps and around all occupied columns.
        const offset = 9 + ((outgoing + source.rank) % 4) * 10;
        externalLanes.set(edge.from, outgoing + 1);
        const onLeft = edge.kind === "fallthrough";
        const side = onLeft ? margin - offset : margin + grid.totalWidth + offset;
        const x2 = destination.x + width / 2;
        const approach = destination.y - offset;
        d = ["M", x1, y1, "V", y1 + offset, "H", side, "V", approach, "H", x2, "V", destination.y].join(" ");
        minX = Math.min(minX, side - 16);
        maxX = Math.max(maxX, side + 16);
      } else {
        // Exit stubs stay below their owning block. The node inspector expands the full reason.
        const x = source.x + 13 + (outgoing % 2) * 146;
        const y = y1 + 22 + Math.floor(outgoing / 2) * 22;
        externalLanes.set(edge.from, outgoing + 1);
        d = ["M", x + 5, y1, "V", y - 4].join(" ");
        const reason = edgeLabel(edge);
        const clicking = edge.target ? "button" : "note";
        const label = shape("g", {class: "flow-exit", role: clicking, "aria-label": reason,
          tabindex: edge.target ? "0" : "-1", transform: "translate(" + x + " " + y + ")"});
        label.append(shape("title", {}, reason), shape("text", {x: 0, y: 11}, reason));
        if (edge.target) activate(label, () => onTarget(edge));
        edges.append(label);
        maxY = Math.max(maxY, y + 28);
      }
      const kind = !destination ? "external" : edge.kind;
      const style = ["branch_taken", "fallthrough", "jump"].includes(kind) ? kind : "external";
      const path = shape("path", {d, class: style, "marker-end": "url(#flow-arrow-" + style + ")"});
      path.append(shape("title", {}, edgeLabel(edge)));
      edges.prepend(path);
      if (!lines.has(edge.from)) lines.set(edge.from, []);
      lines.get(edge.from).push(path);
    }
    for (const {x, y, boxHeight, block} of grid.positions.values()) {
      const group = shape("g", {class: "flow-node", role: "group", "aria-label": "Block " + block.start,
        transform: "translate(" + x + " " + y + ")"});
      group.append(shape("rect", {width, height: boxHeight, rx: 4}));
      const header = shape("g", {class: "flow-header", role: "button", tabindex: 0, "aria-label": "Select block " + block.start});
      header.append(shape("rect", {width, height: 31, rx: 4}), shape("text", {x: 12, y: 20}, block.start));
      if (block.start === graph.function.address) header.append(shape("text", {x: width - 56, y: 20}, "Entry"));
      activate(header, () => onBlock(block));
      group.append(header);
      for (const [index, instruction] of block.instructions.slice(0, 4).entries()) {
        const line = shape("g", {class: "flow-instruction", role: "button", tabindex: 0,
          "aria-label": instruction.address + " " + instruction.text});
        const lineY = 49 + index * 19;
        const text = instruction.text.length > 35 ? instruction.text.slice(0, 34) + "…" : instruction.text;
        line.append(shape("rect", {x: 1, y: lineY - 13, width: width - 2, height: 18}),
          shape("text", {x: 11, y: lineY}, text), shape("title", {}, instruction.address + " " + instruction.text));
        activate(line, () => onInstruction(block, instruction));
        group.append(line);
      }
      if (block.instructions.length > 4) {
        const more = shape("text", {x: width - 45, y: 106, class: "flow-more"}, "+" + (block.instructions.length - 4));
        group.append(more);
      }
      nodes.set(block.start, group);
      blocks.append(group);
    }
    full = [minX, 0, maxX - minX, maxY];
    fit();
  }

  function edgeLabel(edge) {
    const kind = edge.kind.replaceAll("_", " ");
    if (edge.block) return kind + " → " + edge.block;
    if (edge.target) return kind + " → " + edge.target;
    const reason = edge.resolution.replaceAll("_", " ");
    return edge.resolution === "exit" ? kind : kind + " (" + reason + ")";
  }

  function activate(node, action) {
    node.addEventListener("click", () => { if (!moved) action(); });
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        action();
      }
    });
  }

  function update() { svg.setAttribute("viewBox", view.join(" ")); }
  function fit() { view = [...full]; update(); }
  function zoom(scale) {
    if (view[2] * scale > full[2] * 3 || view[2] * scale < Math.min(200, full[2])) return;
    view = [view[0] + view[2] * (1 - scale) / 2, view[1] + view[3] * (1 - scale) / 2,
      view[2] * scale, view[3] * scale];
    update();
  }

  function select(address, instruction) {
    for (const [key, node] of nodes) node.classList.toggle("selected", key === address);
    for (const [key, paths] of lines) {
      for (const path of paths) path.classList.toggle("highlight", key === address);
    }
    for (const node of nodes.values()) {
      for (const row of node.querySelectorAll(".flow-instruction")) {
        row.classList.toggle("selected", !!instruction && row.getAttribute("aria-label").startsWith(instruction + " "));
      }
    }
  }

  svg.addEventListener("wheel", (event) => {
    event.preventDefault();
    zoom(event.deltaY > 0 ? 1.14 : 1 / 1.14);
  }, {passive: false});
  svg.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    moved = false;
    const matrix = svg.getScreenCTM();
    if (!matrix || matrix.a === 0 || matrix.d === 0) return;
    drag = {id: event.pointerId, x: event.clientX, y: event.clientY, scaleX: matrix.a, scaleY: matrix.d, view: [...view]};
  });
  svg.addEventListener("pointermove", (event) => {
    if (drag?.id !== event.pointerId) return;
    const dx = event.clientX - drag.x;
    const dy = event.clientY - drag.y;
    if (!moved && Math.hypot(dx, dy) < 4) return;
    if (!moved) svg.setPointerCapture(event.pointerId);
    moved = true;
    view = [drag.view[0] - dx / drag.scaleX, drag.view[1] - dy / drag.scaleY, drag.view[2], drag.view[3]];
    update();
  });
  for (const type of ["pointerup", "pointercancel", "pointerleave"]) {
    svg.addEventListener(type, () => { drag = null; });
  }
  return {render, fit, zoom, select};
}
