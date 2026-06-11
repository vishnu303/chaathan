// Proxy Tools Installation
//
// Previously housed the proxy-scraper-checker Rust binary downloader.
// That tool has been replaced by proxybroker2 (Python/pip), which is
// now installed by installPythonToolsSection() in python_tools.go.
//
// mubeng (Go) is installed by installGoToolsSection() via go install.
//
// This file is retained to satisfy the setup.go call-site but performs
// no work — all proxy tooling is handled by the appropriate section.
package setup

func installProxyToolsSection() (installed, skipped, failed int) {
	// All proxy tools are now handled by their native installers:
	//   proxybroker  → installPythonToolsSection() (pip)
	//   mubeng       → installGoToolsSection()     (go install)
	return 0, 0, 0
}
