# Connecting `AISidePanel.jsx` to the Backend API

This guide provides immediate technical steps, code snippets, and hooks to connect your React `AISidePanel.jsx` component to the FastAPI backend API controller, render interactive node graph contexts with `react-flow`, and securely generate/lock court-ready dossiers using `jspdf` and server-side SHA-256 cryptographic hashing.

---

## 1. Quick Start: Launching the Backend Server

Ensure Python dependencies (`fastapi`, `uvicorn`, `pydantic`, `eth-utils`) are installed:
```bash
pip install fastapi uvicorn pydantic eth-utils
```

Run the backend server:
```bash
python -m uvicorn src.blockchain.api_controller:app --reload --port 8000
```
The server will start at `http://localhost:8000`. Test the root route in your browser: `http://localhost:8000/`.

---

## 2. React API Service Layer (`src/services/forensicApi.js`)

Create a lightweight API client to talk to the backend:

```javascript
// src/services/forensicApi.js
const API_BASE_URL = 'http://localhost:8000/api/v1/forensics';

export async function investigateTarget(targetAddress, options = {}) {
  const response = await fetch(`${API_BASE_URL}/investigate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target: targetAddress,
      force_refresh: options.forceRefresh || false,
      simulate_llm_failure: options.simulateFailure || false
    })
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || 'Failed to investigate target address.');
  }

  return await response.json();
}

export async function lockToVault(dossierPayload) {
  const response = await fetch(`${API_BASE_URL}/vault/lock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(dossierPayload)
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.detail || 'Failed to lock dossier into cryptographic vault.');
  }

  return await response.json();
}
```

---

## 3. Client-Side PDF Generation (`jspdf`) + Server-Side SHA-256 Hashing

Install `jspdf`:
```bash
npm install jspdf
```

In your `AISidePanel.jsx`, implement the "Lock to Dossier" click handler:

```javascript
import { jsPDF } from 'jspdf';
import { lockToVault } from '../services/forensicApi';

const handleLockToDossier = async (investigationData, investigatorId = "INV-8042") => {
  try {
    // 1. Generate PDF on client side using jsPDF
    const doc = new jsPDF();
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.text("FORENSIC DOSSIER & AUDIT TRAIL", 14, 22);

    doc.setFontSize(11);
    doc.setFont("helvetica", "normal");
    doc.text(`Target: ${investigationData.target}`, 14, 34);
    doc.text(`Composite Risk Score: ${investigationData.risk_evaluation.composite_score}/100`, 14, 42);
    doc.text(`Risk Level: ${investigationData.risk_evaluation.risk_level}`, 14, 50);

    doc.setFont("helvetica", "bold");
    doc.text("Executive Narrative:", 14, 62);
    doc.setFont("helvetica", "normal");
    const splitNarrative = doc.splitTextToSize(investigationData.ai_narrative_result.narrative, 180);
    doc.text(splitNarrative, 14, 70);

    // Convert PDF to base64 string
    const pdfBase64 = doc.output('datauristring').split(',')[1];

    // 2. Send payload to backend for server-side SHA-256 hashing & cryptographic locking
    const lockPayload = {
      investigator_id: investigatorId,
      target: investigationData.target,
      risk_evaluation: investigationData.risk_evaluation,
      ai_narrative_result: investigationData.ai_narrative_result,
      pdf_base64: pdfBase64
    };

    const lockResponse = await lockToVault(lockPayload);

    // 3. Download PDF locally with court-ready SHA-256 proof footer
    const proof = lockResponse.dossier.cryptographic_proof;
    doc.setFontSize(8);
    doc.text(`SHA-256 Digest: ${proof.payload_sha256}`, 14, 280);
    doc.text(`HMAC Proof: ${proof.hmac_signature.slice(0, 32)}...`, 14, 285);
    doc.save(`Forensic_Dossier_${investigationData.target.slice(0, 8)}.pdf`);

    alert(`Dossier Locked! Record ID: ${proof.vault_record_id}`);
  } catch (err) {
    console.error("Lock error:", err);
    alert(`Vault Lock Error: ${err.message}`);
  }
};
```

---

## 4. Interactive Node Graph Context with `react-flow`

Install `reactflow`:
```bash
npm install reactflow
```

Render the returned `graph_context` (`nodes` and `edges`) in your graph view component:

```jsx
import React from 'react';
import ReactFlow, { Background, Controls } from 'reactflow';
import 'reactflow/dist/style.css';

export function InvestigatorNodeGraph({ graphContext }) {
  if (!graphContext || !graphContext.nodes) {
    return <div className="text-gray-400 p-4">No node graph context loaded.</div>;
  }

  return (
    <div style={{ width: '100%', height: '400px' }} className="bg-gray-950 rounded-lg border border-cyan-900/40">
      <ReactFlow nodes={graphContext.nodes} edges={graphContext.edges} fitView>
        <Background color="#1E293B" gap={16} />
        <Controls />
      </ReactFlow>
    </div>
  );
}
```

---

## 5. Summary of Next Immediate Technical Steps

1. **Start Backend Server**: Run `python -m uvicorn src.blockchain.api_controller:app --reload`.
2. **Add API Client**: Copy `forensicApi.js` into your frontend project.
3. **Bind `AISidePanel.jsx` Input**: Connect the search button to `investigateTarget(address)`.
4. **Pass Node Graph**: Render `response.graph_context` inside `<InvestigatorNodeGraph />`.
5. **Trigger Vault Lock**: Bind `handleLockToDossier` to the "Lock to Dossier" button.
