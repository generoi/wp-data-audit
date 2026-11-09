package audit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The real hasher on a fake release: asset manifests get a shape verdict,
// and vendor/autoload.php is hashed with its suffix masked, as the local
// install is. The test's PATH replaces the hasher's (macOS's /usr/bin has
// BSD tools; CI and nix have GNU's).
func TestHasherShapes(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("no sha256sum")
	}
	dir := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("composer.json", "{}")
	build := "web/app/themes/t/build/"
	write(build+"min.asset.php", "<?php return array('dependencies' => array('wp-i18n', 'react-jsx-runtime'), 'version' => 'b5f9218d54d5d61b38f2');\n")
	write(build+"pretty.asset.php", "<?php return array(\n\t'dependencies' => array(\n\t\t'wp-api-fetch',\n\t\t'wp-blocks'\n\t),\n\t'version' => '36c3316b7059b012bad7'\n);\n")
	write(build+"module.asset.php", "<?php return array('dependencies' => array(array('id' => '@wordpress/interactivity', 'import' => 'static')), 'version' => 'a1', 'type' => 'module');\n")
	write(build+"eval.asset.php", "<?php eval($_GET['x']); return array('dependencies' => array(), 'version' => 'a');\n")
	write(build+"call.asset.php", "<?php return array('dependencies' => array(), 'version' => system('id'));\n")
	write(build+"interp.asset.php", "<?php return array('dependencies' => array(), 'version' => \"{${system('id')}}\");\n")
	write(build+"escape.asset.php", "<?php return array('dependencies' => array('a\\'), system(\\'id'), 'version' => 'a');\n")
	write("web/app/uploads/x/skip.asset.php", "<?php system('id');")
	autoload := "<?php\n\nrequire_once __DIR__ . '/composer/autoload_real.php';\n\nreturn ComposerAutoloaderInit7bdbc28be03650b22a8d27644b745c53::getLoader();\n"
	write("vendor/autoload.php", autoload)

	script := strings.Replace(Hasher, "PATH=/usr/bin:/bin ", "PATH='"+os.Getenv("PATH")+"' ", 1)
	cmd := exec.Command("sh", "-s")
	cmd.Dir, cmd.Stdin = dir, strings.NewReader(script)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseFiles(out)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"min": true, "pretty": true, "module": true, "eval": false, "call": false, "interp": false, "escape": false} {
		if got, ok := f.Shapes[build+name+".asset.php"]; !ok || got != want {
			t.Errorf("%s: shape %v (seen %v), want %v", name, got, ok, want)
		}
	}
	if _, ok := f.Shapes["web/app/uploads/x/skip.asset.php"]; ok || len(f.Shapes) != 7 {
		t.Errorf("shapes %v", f.Shapes)
	}
	// The same file elsewhere, another suffix: the same masked hash.
	other := filepath.Join(t.TempDir(), "autoload.php")
	os.WriteFile(other, []byte(strings.Replace(autoload, "7bdbc28be03650b22a8d27644b745c53", "0123456789abcdef0123456789abcdef", 1)), 0o644)
	local, err := hashAutoload(other)
	if err != nil || f.Files["vendor/autoload.php"] != local {
		t.Errorf("autoload %q, local %q %v", f.Files["vendor/autoload.php"], local, err)
	}
}
