import SwiftUI
import WebKit

struct ContentView: View {
    @State private var markdownText: String = "# Welcome to Markdown Editor\n\nType *Markdown* on the left."

    var body: some View {
        HStack {
            TextEditor(text: $markdownText)
                .padding()
                .frame(minWidth: 300)
                .border(Color.gray.opacity(0.3))

            Divider()

            WebView(html: renderMarkdown(markdownText))
                .frame(minWidth: 300)
        }
        .frame(minWidth: 600, minHeight: 400)
    }

    func renderMarkdown(_ text: String) -> String {
        let escaped = text.replacingOccurrences(of: "\n", with: "<br>")
        return "<html><head><style>body { font-family: -apple-system; padding: 1em; }</style></head><body>\(escaped)</body></html>"
    }

}

struct WebView: NSViewRepresentable {
    let html: String
    func makeNSView(context: Context) -> WKWebView {
        let webView = WKWebView()
        webView.loadHTMLString(html, baseURL: nil)
        return webView
    }
    func updateNSView(_ webView: WKWebView, context: Context) {
        webView.loadHTMLString(html, baseURL: nil)
    }

}
