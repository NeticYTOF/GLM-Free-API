// sse_reasoning_split_repro_test.go
//
// Reproduction + regression test for the reasoning_content split/interrupt
// bug reported against the live 2026-09-13 trace:
//
//   The client (OpenAI SDK) receives, in this order:
//     1. reasoning chunks ...             (delta.reasoning_content)
//     2. a BLANK content chunk           (delta.content = "")
//     3. the FINAL reasoning tail chunk   (delta.reasoning_content)
//     4. the real content chunks          (delta.content)
//
//   Expected: reasoning_content fully first, then content.
//
// Root cause fixed here (parser side): the Z.AI upstream CLOSES the
// <details> reasoning block with an edit_content snapshot (the
// "true\">..." event) and then streams the answer. flush() held back the
// last StreamHoldback runes of the reasoning until the FINAL flush, so the
// reasoning tail landed on the client only after the answer had already
// streamed — the "reasoning_content, content, reasoning_content, content"
// interleaving in the trace. Once the details block is closed the
// reasoning is final and must be released in full, before any answer
// content is forwarded.
//
// (The blank-content keep-alive chunk in the same trace is a handler-side
// bug covered by tests/reasoning_split_test.go.)

package zbridge

import (
	"strings"
	"testing"
)

// buildLiveTraceEvents rebuilds the exact SSE event sequence the Z.AI
// upstream sent in the live trace from the bug report (timestamps
// 07:25:25-07:25:31): thinking-phase deltas, the closing edit_content
// snapshot, answer-phase deltas, a usage event, and a trailing answer-tail
// edit_content backtrack — then done.
func buildLiveTraceEvents() []string {
	return []string{
		// 07:25:25 thinking
		`{"type":"chat:completion","data":{"delta_content":"<details type=\"reasoning\" done=\"false\">\n> \n> \n>","phase":"thinking"}}`,
		// 07:25:26 thinking
		`{"type":"chat:completion","data":{"delta_content":" The user is asking me to summarize today's top AI news. However, I don't have access to any tools in this case - the <tools> section shows \"(no tools provided)\". Without","phase":"thinking"}}`,
		// 07:25:27 thinking
		`{"type":"chat:completion","data":{"delta_content":" access to web browsing tools, news APIs, or any other information gathering tools, I cannot access current news or real-time information.\n> \n> I need to respond with plain text since","phase":"thinking"}}`,
		// 07:25:28 thinking
		`{"type":"chat:completion","data":{"delta_content":" no tool applies. I should explain that I don't have access to current news or the internet, and therefore cannot provide a summary of today's AI news.","phase":"thinking"}}`,
		// 07:25:28 answer-opening edit_content snapshot (closes the details
		// block and starts the answer): edit_index 32 truncates back into
		// the <details> opener (right after `done=`) and rewrites the tail.
		`{"type":"chat:completion","data":{"edit_index":32,"edit_content":"true\">\n> \n> \n> The user is asking me to summarize today's top AI news. However, I don't have access to any tools in this case - the <tools> section shows \"(no tools provided)\". Without access to web browsing tools, news APIs, or any other information gathering tools, I cannot access current news or real-time information.\n> \n> I need to respond with plain text since no tool applies. I should explain that I don't have access to current news or the internet, and therefore cannot provide a summary of today's AI news.\n</details>\nI don't have","phase":"answer"}}`,
		// 07:25:29 answer deltas
		`{"type":"chat:completion","data":{"delta_content":" access to the internet, news sources, or real-time information. Without browsing capabilities or news APIs, I cannot retrieve or summarize today's top AI news stories.\n\nTo","phase":"answer"}}`,
		`{"type":"chat:completion","data":{"delta_content":" get current AI news, you might want to check:\n- Tech news sites like TechCrunch, The Verge, or Wired\n- AI-focused publications like VentureBeat AI, AI News,","phase":"answer"}}`,
		`{"type":"chat:completion","data":{"delta_content":" or MIT Technology Review\n- Google News with \"AI\" as a search term\n- Social media platforms where AI researchers and companies share updates\n\nIs there anything else I can","phase":"answer"}}`,
		// 07:25:31 usage (phase other — no content fields)
		`{"type":"chat:completion","data":{"phase":"other","usage":{"prompt_tokens":475,"completion_tokens":231,"total_tokens":706,"prompt_tokens_details":{}}}}`,
		// 07:25:31 answer-tail backtrack in phase other (edit_index 1073)
		`{"type":"chat:completion","data":{"edit_index":1073,"edit_content":" help you with that doesn't require real-time information?","phase":"other"}}`,
		// done
		`{"type":"chat:completion","data":{"phase":"done","done":true}}`,
	}
}

// runLiveTraceParser feeds the live-trace event sequence through the REAL
// streamSSEResponse under the given hold-back and returns the raw results.
func runLiveTraceParser(t *testing.T, hb int) []ZAIResult {
	t.Helper()
	var b strings.Builder
	for _, e := range buildLiveTraceEvents() {
		b.WriteString("data: " + e + "\n\n")
	}
	var res []ZAIResult
	withHoldback(t, hb, func() {
		res = runSSEParser(t, b.String())
	})
	return res
}

// wantLiveTraceReasoning is the complete reasoning body the client must
// receive — the <details> body with the markdown quote markers stripped,
// exactly what the live trace's reasoning chunks concatenated to.
const wantLiveTraceReasoning = "The user is asking me to summarize today's top AI news. " +
	"However, I don't have access to any tools in this case - the <tools> section shows \"(no tools provided)\". " +
	"Without access to web browsing tools, news APIs, or any other information gathering tools, " +
	"I cannot access current news or real-time information.\n\n" +
	"I need to respond with plain text since no tool applies. I should explain that I don't have access " +
	"to current news or the internet, and therefore cannot provide a summary of today's AI news."

// wantLiveTraceContent is the answer the client must receive — the text
// after </details>, with the phase-other tail backtrack applied the way the
// append-only client converges on it ("hel" + "p you" = "help you").
const wantLiveTraceContent = "\nI don't have access to the internet, news sources, or real-time information. " +
	"Without browsing capabilities or news APIs, I cannot retrieve or summarize today's top AI news stories.\n\n" +
	"To get current AI news, you might want to check:\n" +
	"- Tech news sites like TechCrunch, The Verge, or Wired\n" +
	"- AI-focused publications like VentureBeat AI, AI News, or MIT Technology Review\n" +
	"- Google News with \"AI\" as a search term\n" +
	"- Social media platforms where AI researchers and companies share updates\n\n" +
	"Is there anything else I can help you with that doesn't require real-time information?"

// TestReasoningCompleteBeforeContent drives the REAL parser with the exact
// live-trace events and asserts the client-visible ordering:
//   1. every reasoning delta arrives strictly before the first content delta
//      (the reported split released the reasoning tail only at the final
//      flush, AFTER the answer had streamed);
//   2. the concatenated reasoning is the complete <details> body;
//   3. the concatenated content converges on the expected answer.
func TestReasoningCompleteBeforeContent(t *testing.T) {
	for _, hb := range []int{0, 24} {
		results := runLiveTraceParser(t, hb)

		reasoningAll, contentAll := "", ""
		lastReasoningIdx, firstContentIdx := -1, -1
		for i, r := range results {
			if r.Reasoning != "" {
				reasoningAll += r.Reasoning
				lastReasoningIdx = i
			}
			if r.Chunk != "" && firstContentIdx < 0 {
				firstContentIdx = i
			}
			if r.Chunk != "" {
				contentAll += r.Chunk
			}
		}

		if reasoningAll == "" || contentAll == "" {
			t.Fatalf("holdback=%d: expected both reasoning and content, got reasoning=%q content=%q", hb, reasoningAll, contentAll)
		}
		if lastReasoningIdx > firstContentIdx {
			t.Errorf("holdback=%d: reasoning delta #%d arrived AFTER first content delta #%d — reasoning/content interleaved (the reported split)", hb, lastReasoningIdx, firstContentIdx)
		}
		if reasoningAll != wantLiveTraceReasoning {
			t.Errorf("holdback=%d: reasoning mismatch\n got: %q\nwant: %q", hb, reasoningAll, wantLiveTraceReasoning)
		}
		if contentAll != wantLiveTraceContent {
			t.Errorf("holdback=%d: content mismatch\n got: %q\nwant: %q", hb, contentAll, wantLiveTraceContent)
		}
	}
}

// TestReasoningReleasedWhenBlockCloses isolates the fix: the moment the
// </details> close tag completes in the raw text, the pending reasoning
// tail must be released — not deferred to the final flush — so a long
// answer that follows never precedes the reasoning tail on the client.
func TestReasoningReleasedWhenBlockCloses(t *testing.T) {
	withHoldback(t, 24, func() {
		quoted := "> " + strings.Repeat("reasoning text ", 20) // well past the hold-back window
		full := "<details>" + quoted + "</details>" + strings.Repeat("answer text ", 50)
		results := runSSEParser(t, editAppendStream(full))

		// Find the index of the last reasoning delta and the first content
		// delta: reasoning must be complete before any content flows.
		lastReasoning, firstContent := -1, -1
		for i, r := range results {
			if r.Reasoning != "" {
				lastReasoning = i
			}
			if r.Chunk != "" && firstContent < 0 {
				firstContent = i
			}
		}
		if lastReasoning > firstContent {
			t.Errorf("reasoning tail deferred past content: last reasoning #%d vs first content #%d", lastReasoning, firstContent)
		}

		// stripDetailsTags TrimSpaces the body, so the trailing space of the
		// final repeat is dropped — expected.
		want := strings.TrimSpace(strings.Repeat("reasoning text ", 20))
		if got := collectReasoning(results); got != want {
			t.Errorf("reasoning = %q, want %q", got, want)
		}
		clientText, _ := replayClientView(results)
		if want := strings.Repeat("answer text ", 50); clientText != want {
			t.Errorf("content = %q, want %q", clientText, want)
		}
	})
}
