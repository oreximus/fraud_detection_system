{
  "$schema": "https://schemas.plasmo.com/schemas/1.0.0/config.json",
  "name": "Fraud Agent Browser Extension",
  "version": "0.1.0",
  "description": "Privacy-first fraud detection browser extension",
  "entryPoints": {
    "background": "src/background/index.ts",
    "content-script": "src/content-script/index.ts",
    "popup": "src/popup/index.tsx"
  },
  "devEntries": {
    "popup": "src/popup/index.tsx"
  },
  "alias": {
    "components": "src/components",
    "utils": "src/utils",
    "hooks": "src/hooks"
  },
  "permissions": [
    "storage",
    "tabs",
    "activeTab",
    "scripting"
  ],
  "hostPermissions": [
    "<all_urls>"
  ],
  "browserArguments": [],
  "webpack": {
    "externals": {
      "axios": "axios"
    }
  },
  "outputDir": "dist",
  "deploy": {
    "allowJsInjection": true
  }
}