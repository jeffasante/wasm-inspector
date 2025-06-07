import init, { analyze_wasm_bytes_for_web } from './pkg/wasm_inspector.js'; 

async function main() {
    await init();

    // ... (all your const declarations for DOM elements remain the same) ...
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const uploadStatus = document.getElementById('upload-status');
    const fileDetailsDiv = document.getElementById('file-details');
    const fileNameDisplay = document.getElementById('file-name-display');
    const fileSizeDisplay = document.getElementById('file-size-display');
    const analysisOutputSection = document.getElementById('analysis-output');
    const tabLinks = document.querySelectorAll('.tab-link');
    const tabPanes = document.querySelectorAll('.tab-pane');

    const summaryInfoGrid = document.getElementById('summary-info-grid');
    const structureDetails = document.getElementById('structure-details');
    const callGraphStats = document.getElementById('call-graph-stats');
    const securityDetails = document.getElementById('security-details');
    const performanceDetailsGrid = document.getElementById('performance-details');
    const memoryDetails = document.getElementById('memory-details');
    const compatibilityDetails = document.getElementById('compatibility-details');
    const rawJsonOutput = document.getElementById('raw-json-output');
    
    let currentAnalysisData = null; // Store the analysis data globally within this scope

    // --- Event Listeners ---
    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => e.target.files.length && handleFile(e.target.files[0]));
    dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        e.dataTransfer.files.length && handleFile(e.dataTransfer.files[0]);
    });

    tabLinks.forEach(link => {
        link.addEventListener('click', () => {
            tabLinks.forEach(l => l.classList.remove('active'));
            tabPanes.forEach(p => p.classList.remove('active'));
            
            link.classList.add('active');
            const activeTabPane = document.getElementById(link.dataset.tab);
            activeTabPane.classList.add('active');

            // ***** NEW: Render D3 graph only if its tab is now active and data exists *****
            if (link.dataset.tab === 'call-graph' && currentAnalysisData && currentAnalysisData.call_graph) {
                renderCallGraph(currentAnalysisData.call_graph);
            }
        });
    });

    async function handleFile(file) {
        if (!file.name.endsWith('.wasm')) {
            updateStatus('Please upload a .wasm file.', 'error');
            return;
        }
        updateStatus(`Processing ${file.name}...`, 'info');
        fileNameDisplay.textContent = file.name;
        fileSizeDisplay.textContent = file.size;
        fileDetailsDiv.style.display = 'block';
        analysisOutputSection.style.display = 'none';
        currentAnalysisData = null; // Reset data

        const reader = new FileReader();
        reader.onload = async (e) => {
            try {
                updateStatus(`Analyzing ${file.name}...`, 'info');
                const analysisJsonString = analyze_wasm_bytes_for_web(new Uint8Array(e.target.result));
                currentAnalysisData = JSON.parse(analysisJsonString); // Store data
                
                updateStatus(`Analysis complete for ${file.name}.`, 'success');
                displayResults(currentAnalysisData); // Populate non-D3 parts
                analysisOutputSection.style.display = 'block';
                tabLinks[0].click(); // Activate summary tab (which will trigger its own tab logic)
            } catch (error) {
                console.error("Analysis error:", error);
                updateStatus(`Error: ${error.message || error.toString()}`, 'error');
                currentAnalysisData = null;
            }
        };
        reader.onerror = () => {
            updateStatus('Error reading file.', 'error');
            currentAnalysisData = null;
        };
        reader.readAsArrayBuffer(file);
    }

    function updateStatus(message, type = 'info') {
        uploadStatus.textContent = message;
        uploadStatus.className = `status-text ${type}`;
    }

    function createInfoItem(label, value) {
        const item = document.createElement('div');
        item.classList.add('info-item');
        item.innerHTML = `<strong>${label}:</strong> <span>${value !== null && value !== undefined ? value : 'N/A'}</span>`;
        return item;
    }
    
    function createTable(headers, rowsData, captionText = '') {
        const table = document.createElement('table');
        table.classList.add('styled-table');
        if (captionText) {
            const caption = table.createCaption();
            caption.innerHTML = `<strong>${captionText}</strong>`; // Make caption bold
        }
        const thead = table.createTHead();
        const headerRow = thead.insertRow();
        headers.forEach(headerText => {
            const th = document.createElement('th');
            th.textContent = headerText;
            headerRow.appendChild(th);
        });
        const tbody = table.createTBody();
        if (rowsData.length === 0) {
            const row = tbody.insertRow();
            const cell = row.insertCell();
            cell.colSpan = headers.length;
            cell.textContent = "No data available.";
            cell.style.textAlign = "center";
        } else {
            rowsData.forEach(rowData => {
                const row = tbody.insertRow();
                rowData.forEach(cellData => {
                    const cell = row.insertCell();
                    // If cellData is an object/array, stringify it prettily for pre, else just text
                    if (typeof cellData === 'object' && cellData !== null) {
                        const pre = document.createElement('pre');
                        pre.style.margin = '0'; // Remove default pre margin
                        pre.style.backgroundColor = 'transparent'; // Inherit
                        pre.style.border = 'none';
                        pre.textContent = JSON.stringify(cellData, null, 2);
                        cell.appendChild(pre);
                    } else {
                         cell.textContent = cellData !== null && cellData !== undefined ? cellData : 'N/A';
                    }
                });
            });
        }
        return table;
    }

    function displayResults(data) {
        // Clear previous results from all panes (except raw JSON which is populated last)
        summaryInfoGrid.innerHTML = '';
        structureDetails.innerHTML = '';
        securityDetails.innerHTML = '';
        performanceDetailsGrid.innerHTML = '';
        memoryDetails.innerHTML = '';
        compatibilityDetails.innerHTML = '';
        callGraphStats.textContent = "Graph data will be rendered when tab is active.";
        d3.select("#call-graph-svg").selectAll("*").remove(); // Clear graph explicitly

        const mi = data.module_info;
        const sa = data.security_analysis;
        const pa = data.performance_metrics;
        const comp = data.compatibility;
        const ma = data.memory_analysis;

        // 1. Summary Tab
        const importedFuncCount = mi.imports.filter(i => i.kind.Function !== undefined).length;
        const definedFuncCount = mi.functions.length;
        summaryInfoGrid.appendChild(createInfoItem('WASM Version', mi.version));
        summaryInfoGrid.appendChild(createInfoItem('Total Functions', importedFuncCount + definedFuncCount));
        summaryInfoGrid.appendChild(createInfoItem('Imported Functions', importedFuncCount));
        summaryInfoGrid.appendChild(createInfoItem('Defined Functions', definedFuncCount));
        summaryInfoGrid.appendChild(createInfoItem('Total Imports', mi.imports.length));
        summaryInfoGrid.appendChild(createInfoItem('Total Exports', mi.exports.length));
        summaryInfoGrid.appendChild(createInfoItem('Has Memory', mi.memory ? 'Yes' : 'No'));
        summaryInfoGrid.appendChild(createInfoItem('Has Start Function', mi.start_function !== null ? `Yes (Index: ${mi.start_function})` : 'No'));
        summaryInfoGrid.appendChild(createInfoItem('Uses WASI', sa.wasi_usage.uses_wasi ? `Yes (${sa.wasi_usage.wasi_version || 'Unknown'})` : 'No'));
        summaryInfoGrid.appendChild(createInfoItem('Detected Language', comp.detected_language || 'Undetermined'));
        const overallRisk = sa.capabilities.reduce((maxRisk, cap) => {
            const riskOrder = { "Low": 1, "Medium": 2, "High": 3, "Critical": 4 };
            return riskOrder[cap.risk_level] > riskOrder[maxRisk] ? cap.risk_level : maxRisk;
        }, "Low");
        summaryInfoGrid.appendChild(createInfoItem('Overall Risk (heuristic)', `[${overallRisk.toUpperCase()}]`));

        // 2. Structure Tab
        const sectionCounts = [
            ['Type Signatures', mi.type_signatures.length],
            ['Total Imports', mi.imports.length],
            ['Total Exports', mi.exports.length],
            ['Defined Functions', mi.functions.length],
            ['Globals', mi.globals.length],
            ['Tables', mi.tables.length],
            ['Memory Sections', mi.memory ? 1 : 0],
            ['Data Segments', mi.data_segments.length],
            ['Element Segments', mi.element_segments.length],
            ['Custom Sections', mi.custom_sections.length],
        ];
        structureDetails.appendChild(createTable(['Section Type', 'Count'], sectionCounts, 'Module Section Counts'));
        
        if (mi.imports.length > 0) {
            structureDetails.appendChild(createTable(
                ['Module', 'Name', 'Kind', 'Details'],
                mi.imports.slice(0, 20).map(imp => [ // Limit to first 20 for display
                    imp.module, 
                    imp.name, 
                    Object.keys(imp.kind)[0], 
                    imp.kind.Function ? `Type Index: ${imp.kind.Function.type_index}` : 
                    imp.kind.Table ? `Elem: ${imp.kind.Table.table_type.element_type}, Init: ${imp.kind.Table.table_type.initial}, Max: ${imp.kind.Table.table_type.maximum || '-'}` : 
                    imp.kind.Memory ? `Init: ${imp.kind.Memory.memory_type.initial}p, Max: ${imp.kind.Memory.memory_type.maximum || '-'}p, Shared: ${imp.kind.Memory.memory_type.shared}` :
                    imp.kind.Global ? `Type: ${imp.kind.Global.global_type.value_type}, Mut: ${imp.kind.Global.global_type.mutable}` : '-'
                ]), `Imports (showing up to 20 of ${mi.imports.length})`
            ));
        }
         if (mi.exports.length > 0) {
             structureDetails.appendChild(createTable(
                ['Name', 'Kind', 'Index'],
                mi.exports.slice(0, 20).map(exp => [exp.name, exp.kind, exp.index]), // exp.kind is already simple enum string
                `Exports (showing up to 20 of ${mi.exports.length})`
            ));
        }
        // TODO: Add more tables for Functions, Globals, etc. for the Structure tab

        // 4. Security Tab (Example for Capabilities)
        if (sa.capabilities.length > 0) {
            const capHeader = document.createElement('h4'); capHeader.textContent = 'Detected Capabilities'; securityDetails.appendChild(capHeader);
            const capList = document.createElement('ul'); capList.classList.add('info-list');
            sa.capabilities.forEach(cap => {
                const li = document.createElement('li'); li.classList.add('info-list-item');
                li.innerHTML = `<strong>${cap.name} <span class="risk-${cap.risk_level.toLowerCase()}">[${cap.risk_level.toUpperCase()}]</span></strong>
                                <p>${cap.description}</p>
                                ${cap.evidence.length > 0 ? `<small>Evidence: ${cap.evidence.join(', ')}</small>` : ''}`;
                capList.appendChild(li);
            });
            securityDetails.appendChild(capList);
        } else {
            securityDetails.appendChild(document.createElement('p')).textContent = 'No specific capabilities detected.';
        }
        // TODO: Display vulnerabilities, WASI usage, sandbox compatibility similarly

        // 5. Performance Tab
        performanceDetailsGrid.innerHTML = '';
        performanceDetailsGrid.appendChild(createInfoItem('Module Size', `${pa.module_size} bytes`));
        // ... (add other performance items using createInfoItem) ...
        if (pa.optimization_suggestions.length > 0) {
            const optHeader = document.createElement('h4'); optHeader.textContent = 'Optimization Suggestions'; performanceDetailsGrid.appendChild(optHeader);
            const optList = document.createElement('ul'); optList.classList.add('info-list');
            pa.optimization_suggestions.forEach(sug => {
                const li = document.createElement('li'); li.classList.add('info-list-item');
                li.innerHTML = `<strong>${sug.category}</strong>: ${sug.description} ${sug.potential_savings ? `(Savings: ${sug.potential_savings})` : ''}`;
                optList.appendChild(li);
            });
            // To make it span full width if needed, append to performanceDetails instead of grid
            document.getElementById('performance').appendChild(optList); // Append list to the tab pane directly
        }


        // 6. Memory Tab
        memoryDetails.innerHTML = ''; // Clear previous
        const memLayoutTitle = document.createElement('h4'); memLayoutTitle.textContent = 'Memory Layout'; memoryDetails.appendChild(memLayoutTitle);
        const memLayoutGrid = document.createElement('div'); memLayoutGrid.classList.add('info-grid');
        memLayoutGrid.appendChild(createInfoItem('Initial Size', `${ma.memory_layout.total_initial_size} bytes`));
        // ... more memory layout items ...
        memoryDetails.appendChild(memLayoutGrid);
        // TODO: Display memory operations, allocation patterns, hotspots, safety in a structured way.

        // 7. Compatibility Tab
        // TODO: Display compatibility in a structured way (e.g., a list for each runtime)
        compatibilityDetails.innerHTML = '';
        const compMatrix = data.compatibility;
        const runtimes = [
            { name: "Wasmtime", status: compMatrix.wasmtime },
            { name: "Wasmer", status: compMatrix.wasmer },
            { name: "Browser", status: compMatrix.browser },
            { name: "Node.js", status: compMatrix.node_js },
            { name: "Deno", status: compMatrix.deno },
            { name: "Cloudflare Workers", status: compMatrix.cloudflare_workers },
        ];
        const compList = document.createElement('ul'); compList.classList.add('info-list');
        runtimes.forEach(rt => {
            const li = document.createElement('li'); li.classList.add('info-list-item');
            let issuesText = rt.status.issues.length > 0 ? `Issues: ${rt.status.issues.join(', ')}` : 'No specific issues.';
            let featuresText = rt.status.required_features.length > 0 ? `Requires: ${rt.status.required_features.join(', ')}` : '';
            li.innerHTML = `<strong>${rt.name}: <span class="${rt.status.compatible ? 'text-success' : 'text-danger'}">${rt.status.compatible ? '[COMPATIBLE]' : '[ISSUES]'}</span></strong>
                            <small>${issuesText} ${featuresText}</small>`;
            compList.appendChild(li);
        });
        compatibilityDetails.appendChild(compList);
        if(compMatrix.detected_language) {
            compatibilityDetails.appendChild(createInfoItem('Detected Language (Heuristic)', compMatrix.detected_language));
        }


        // 8. Raw JSON Tab
        rawJsonOutput.textContent = JSON.stringify(data, null, 2);
    }
    
    // renderCallGraph function remains largely the same as previous, ensure console logs are in place for debugging it
    function renderCallGraph(graphData) {
        console.log('Rendering Call Graph with data:', JSON.parse(JSON.stringify(graphData))); 

        const svg = d3.select("#call-graph-svg");
        svg.selectAll("*").remove(); 

        const wrapper = document.getElementById('call-graph-wrapper');
        if (!wrapper) {
            console.error("Call graph wrapper not found!");
            callGraphStats.textContent = "Error: Graph container not found.";
            return;
        }
        
        // Ensure wrapper is visible and has dimensions
        if (wrapper.offsetParent === null) { // Check if element or its parents are display:none
            console.warn("Call graph wrapper is not visible. Graph may not render correctly until tab is active.");
            callGraphStats.textContent = "Graph will render when this tab is active.";
            // We've moved the renderCallGraph call to when the tab is clicked, so this check might be redundant
            // but good for initial load if the tab was somehow pre-activated without dimensions.
        }

        const width = wrapper.clientWidth;
        const height = wrapper.clientHeight > 0 ? wrapper.clientHeight : 550; // Use wrapper's height or fallback

        console.log('SVG Container Dimensions:', width, height);
        if (width === 0 || height === 0) {
            console.warn("SVG container has zero width or height. Graph may not be visible.");
            callGraphStats.textContent = "Graph container has no dimensions. Ensure tab is visible.";
            return;
        }
        svg.attr("viewBox", `0 0 ${width} ${height}`);

        const nodesInput = Array.isArray(graphData.nodes) ? graphData.nodes : [];
        const edgesInput = Array.isArray(graphData.edges) ? graphData.edges : [];

        if (nodesInput.length === 0) {
            console.log("No nodes to render in call graph.");
            callGraphStats.textContent = `Graph: ${nodesInput.length} nodes, ${edgesInput.length} edges. No data to display visually.`;
            return;
        }
        
        let nodes = nodesInput.map(d => ({ ...d })); // Create mutable copies
        const links = edgesInput.map(d => ({ 
            source: d.from, 
            target: d.to, 
            call_sites: d.call_sites 
        }));

        const nodeMap = new Map();
        nodes.forEach(node => nodeMap.set(node.function_index, node));

        links.forEach(link => {
            if (!nodeMap.has(link.source)) {
                console.warn(`Creating dummy source node for index: ${link.source}`);
                const dummyNode = { id: link.source, function_index: link.source, name: `ext_${link.source}`, is_imported: true, is_exported: false, call_count: 0 };
                nodes.push(dummyNode); // Add to the main nodes array D3 will use
                nodeMap.set(link.source, dummyNode);
            }
            if (!nodeMap.has(link.target)) {
                console.warn(`Creating dummy target node for index: ${link.target}`);
                const dummyNode = { id: link.target, function_index: link.target, name: `ext_${link.target}`, is_imported: true, is_exported: false, call_count: 0 };
                nodes.push(dummyNode); // Add to the main nodes array D3 will use
                nodeMap.set(link.target, dummyNode);
            }
        });
        
        const validLinks = links.filter(link => nodeMap.has(link.source) && nodeMap.has(link.target));
        console.log('Node Map Size:', nodeMap.size, 'Nodes for D3:', nodes.length);
        console.log('Original Links:', links.length, 'Valid Links for D3:', validLinks.length);
        
        callGraphStats.textContent = `Graph: ${nodes.length} nodes, ${validLinks.length} edges. Entry points: ${graphData.entry_points.join(', ') || 'None'}. Unreachable (defined): ${graphData.unreachable_functions.length}.`;
        
        if (nodes.length === 0 || (nodes.length > 0 && validLinks.length === 0 && nodes.length < 5 )) { // if only a few nodes and no edges, don't bother with complex simulation
             if (nodes.length > 0) {
                const g = svg.append("g");
                 g.selectAll("circle")
                    .data(nodes)
                    .join("circle")
                    .attr("cx", (d,i) => 50 + i * 50)
                    .attr("cy", height / 2)
                    .attr("r", 10)
                    .attr("fill", "#000000")
                    .append("title").text(d => `Index: ${d.function_index}\nName: ${d.name || 'N/A'}`);
                g.selectAll("text")
                    .data(nodes)
                    .join("text")
                    .attr("x", (d,i) => 50 + i * 50)
                    .attr("y", height / 2 + 25)
                    .text(d => (d.name || `f_${d.function_index}`).substring(0,10))
                    .attr("font-size", "10px")
                    .attr("text-anchor", "middle")
                    .attr("fill", "#000000");
             }
            return; // Don't run simulation for no links or very few nodes without links
        }


        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(validLinks)
                .id(d => d.function_index)
                .distance(120) 
                .strength(0.3)) 
            .force("charge", d3.forceManyBody().strength(-200)) 
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("x", d3.forceX(width/2).strength(0.015)) 
            .force("y", d3.forceY(height/2).strength(0.015))
            .on("tick", ticked);

        const g = svg.append("g");

        const linkElements = g.append("g")
            .attr("stroke-opacity", 0.4)
            .selectAll("line")
            .data(validLinks)
            .join("line")
            .attr("stroke", "var(--text-color-secondary, #555555)")
            .attr("stroke-width", d => Math.min(3, 0.5 + Math.sqrt(d.call_sites || 1) / 3));

        const nodeElements = g.append("g")
            .selectAll("g")
            .data(nodes)
            .join("g")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

        nodeElements.append("circle")
            .attr("r", d => {
                let baseRadius = d.is_imported ? 6 : (d.is_exported ? 8 : 4);
                let unreachable = graphData.unreachable_functions && graphData.unreachable_functions.includes(d.function_index);
                return Math.min(15, baseRadius + (d.call_count / 5) + (unreachable ? -1 : 0) );
            })
            .attr("fill", d => {
                if (graphData.unreachable_functions && graphData.unreachable_functions.includes(d.function_index) && !d.is_imported) return "#cccccc"; 
                if (d.is_imported) return "#888888"; 
                if (d.is_exported) return "#000000"; 
                return "#333333"; 
            })
            .attr("stroke", "var(--background-color, #ffffff)")
            .attr("stroke-width", 1.5);
        
        nodeElements.append("text")
            .text(d => (d.name || `f_${d.function_index}`).substring(0, 15))
            .attr("fill", "var(--text-color-primary, #000000)")
            .attr("font-family", "var(--font-family-main)")
            .attr("font-size", "9px")
            .attr("dx", 0) 
            .attr("dy", d => { 
                let baseRadius = d.is_imported ? 6 : (d.is_exported ? 8 : 4);
                let r = Math.min(15, baseRadius + (d.call_count / 5));
                return -(r + 5); // Position above circle
             }) 
            .attr("text-anchor", "middle");
        
        nodeElements.append("title")
            .text(d => `Index: ${d.function_index}\nName: ${d.name || 'N/A'}\nType: ${d.is_imported ? 'Imported' : (d.is_exported ? 'Exported' : 'Internal')}${graphData.unreachable_functions && graphData.unreachable_functions.includes(d.function_index) && !d.is_imported ? ' [UNREACHABLE]' : ''}\nCalled: ${d.call_count} times`);

        function ticked() {
            linkElements
                .attr("x1", d => nodeMap.get(d.source.function_index)?.x || 0)
                .attr("y1", d => nodeMap.get(d.source.function_index)?.y || 0)
                .attr("x2", d => nodeMap.get(d.target.function_index)?.x || 0)
                .attr("y2", d => nodeMap.get(d.target.function_index)?.y || 0);
            nodeElements
                .attr("transform", d => `translate(${d.x || 0},${d.y || 0})`);
        }
        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x; d.fy = d.y;
        }
        function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null; d.fy = null;
        }

        svg.call(d3.zoom().scaleExtent([0.1, 5]).on("zoom", event => {
            g.attr("transform", event.transform);
        }));
    }
}
main().catch(console.error);