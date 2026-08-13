package ir.sayeh.stego;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.view.WindowManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The whole UI. Every cryptographic operation is delegated to {@link Stego},
 * which shares its wire format with the Go command line tool.
 */
public class MainActivity extends Activity {

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());

    private Button tabHide, tabReveal;
    private LinearLayout cardHide, cardReveal, cardResult;
    private EditText inputCover, inputSecret, inputPassword, inputStego, inputPasswordReveal;
    private CheckBox showPassword;
    private Spinner spinnerCodec;
    private ProgressBar progress;
    private TextView status, output;

    private String outputText = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Keep secrets out of screenshots, screen recordings and the recent
        // apps thumbnail. This is a tool for hiding messages; showing them in
        // the task switcher would undo the point of it.
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);

        setContentView(R.layout.activity_main);
        bindViews();
        wireUp();
        selectTab(true);
        handleSharedText(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleSharedText(intent);
    }

    @Override
    public void onSaveInstanceState(Bundle out, PersistableBundle persistent) {
        // Deliberately not calling through with the field contents: nothing
        // typed here should be written to disk by the framework.
        super.onSaveInstanceState(out, persistent);
    }

    @Override
    protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }

    private void bindViews() {
        tabHide = findViewById(R.id.tab_hide);
        tabReveal = findViewById(R.id.tab_reveal);
        cardHide = findViewById(R.id.card_hide);
        cardReveal = findViewById(R.id.card_reveal);
        cardResult = findViewById(R.id.card_result);
        inputCover = findViewById(R.id.input_cover);
        inputSecret = findViewById(R.id.input_secret);
        inputPassword = findViewById(R.id.input_password);
        inputStego = findViewById(R.id.input_stego);
        inputPasswordReveal = findViewById(R.id.input_password_reveal);
        showPassword = findViewById(R.id.check_show_password);
        spinnerCodec = findViewById(R.id.spinner_codec);
        progress = findViewById(R.id.progress);
        status = findViewById(R.id.status);
        output = findViewById(R.id.output);
    }

    private void wireUp() {
        ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(
                this, R.array.codec_labels, android.R.layout.simple_spinner_item);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerCodec.setAdapter(adapter);

        tabHide.setOnClickListener(v -> selectTab(true));
        tabReveal.setOnClickListener(v -> selectTab(false));

        showPassword.setOnCheckedChangeListener((b, checked) -> {
            applyPasswordVisibility(inputPassword, checked);
            applyPasswordVisibility(inputPasswordReveal, checked);
        });

        findViewById(R.id.btn_hide).setOnClickListener(v -> doHide());
        findViewById(R.id.btn_reveal).setOnClickListener(v -> doReveal());
        findViewById(R.id.btn_scan).setOnClickListener(v -> doScan());
        findViewById(R.id.btn_clean).setOnClickListener(v -> doClean());
        findViewById(R.id.btn_paste).setOnClickListener(v -> doPaste());
        findViewById(R.id.btn_copy).setOnClickListener(v -> doCopy());
        findViewById(R.id.btn_share).setOnClickListener(v -> doShare());
        findViewById(R.id.btn_clear).setOnClickListener(v -> doClear());
    }

    private void applyPasswordVisibility(EditText field, boolean visible) {
        int start = field.getSelectionStart();
        if (visible) {
            field.setInputType(InputType.TYPE_CLASS_TEXT
                    | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
            field.setTransformationMethod(null);
        } else {
            field.setInputType(InputType.TYPE_CLASS_TEXT
                    | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            field.setTransformationMethod(PasswordTransformationMethod.getInstance());
        }
        field.setSelection(Math.max(0, Math.min(start, field.length())));
    }

    private void selectTab(boolean hide) {
        tabHide.setSelected(hide);
        tabReveal.setSelected(!hide);
        cardHide.setVisibility(hide ? View.VISIBLE : View.GONE);
        cardReveal.setVisibility(hide ? View.GONE : View.VISIBLE);
    }

    /** Accepts text shared into the app from another application. */
    private void handleSharedText(Intent intent) {
        if (intent == null || !Intent.ACTION_SEND.equals(intent.getAction())) {
            return;
        }
        CharSequence shared = intent.getCharSequenceExtra(Intent.EXTRA_TEXT);
        if (shared == null) {
            return;
        }
        inputStego.setText(shared.toString());
        selectTab(false);
        showStatus("Text received. Tap " + getString(R.string.btn_reveal)
                + " or " + getString(R.string.btn_scan) + ".");
    }

    // -----------------------------------------------------------------------
    // Actions
    // -----------------------------------------------------------------------

    private void doHide() {
        String cover = inputCover.getText().toString();
        String secret = inputSecret.getText().toString();
        String password = inputPassword.getText().toString();

        if (secret.isEmpty()) {
            toast("Enter a secret message first.");
            return;
        }

        Stego.Options opts = new Stego.Options();
        opts.password = password;
        opts.codec = spinnerCodec.getSelectedItemPosition() == 1 ? ZwCodec.B2 : ZwCodec.B4;

        busy(password.isEmpty() ? R.string.working : R.string.deriving);

        worker.execute(() -> {
            try {
                Stego.Hidden hidden = Stego.hide(cover, secret, opts);
                ui.post(() -> {
                    idle();
                    setOutput(hidden.text);
                    showStatus(describe(hidden.report)
                            + (password.isEmpty()
                            ? "\n⚠ Not encrypted — anyone who knows the trick can read it."
                            : ""));
                });
            } catch (StegoException e) {
                ui.post(() -> {
                    idle();
                    showStatus("✖ " + e.getMessage());
                });
            }
        });
    }

    private void doReveal() {
        String text = inputStego.getText().toString();
        String password = inputPasswordReveal.getText().toString();

        if (text.isEmpty()) {
            toast("Paste the text that carries the message first.");
            return;
        }

        busy(R.string.working);

        worker.execute(() -> {
            try {
                Stego.Scanned scanned = Stego.scan(text);

                if (scanned.needsPassword() && password.isEmpty()) {
                    ui.post(() -> {
                        idle();
                        showStatus("🔒 This payload is encrypted. Enter the password and try again.");
                    });
                    return;
                }
                if (scanned.needsPassword()) {
                    ui.post(() -> showStatus(getString(R.string.deriving)));
                }

                String secret = scanned.legacySecret != null
                        ? scanned.legacySecret
                        : Stego.unseal(scanned.container, password);

                ui.post(() -> {
                    idle();
                    setOutput(secret);
                    showStatus("✔ Extracted · " + describe(scanned.report));
                });
            } catch (StegoException e) {
                ui.post(() -> {
                    idle();
                    showStatus("✖ " + explain(e, text));
                });
            }
        });
    }

    private void doScan() {
        String text = inputStego.getText().toString();
        if (text.isEmpty()) {
            toast("Nothing to scan.");
            return;
        }
        try {
            Stego.Scanned scanned = Stego.scan(text);
            String verdict = scanned.needsPassword()
                    ? "🔒 Encrypted payload found. It stays sealed until you supply the password."
                    : "🔓 Unencrypted payload found.";
            showStatus(verdict + "\n" + describe(scanned.report));
        } catch (StegoException e) {
            showStatus("✖ " + explain(e, text));
        }
    }

    private void doClean() {
        String text = inputStego.getText().toString();
        int n = ZwCodec.countCarriers(text);
        if (n == 0) {
            showStatus("This text contains no invisible characters.");
            return;
        }
        setOutput(ZwCodec.strip(text));
        showStatus("Removed " + n + " invisible characters.");
    }

    private void doPaste() {
        ClipboardManager cb = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = cb == null ? null : cb.getPrimaryClip();
        if (clip == null || clip.getItemCount() == 0) {
            toast(getString(R.string.paste_empty));
            return;
        }
        CharSequence text = clip.getItemAt(0).coerceToText(this);
        if (text == null || text.length() == 0) {
            toast(getString(R.string.paste_empty));
            return;
        }
        inputStego.setText(text.toString());
        showStatus("Pasted " + text.length() + " characters ("
                + ZwCodec.countCarriers(text.toString()) + " invisible).");
    }

    private void doCopy() {
        if (outputText.isEmpty()) {
            toast(getString(R.string.nothing_to_copy));
            return;
        }
        ClipboardManager cb = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cb == null) {
            return;
        }
        ClipData clip = ClipData.newPlainText("Sayeh", outputText);

        // Ask the system not to show this in the clipboard preview toast.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            android.os.PersistableBundle extras = new android.os.PersistableBundle();
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
            clip.getDescription().setExtras(extras);
        }

        cb.setPrimaryClip(clip);
        toast(getString(R.string.copied));
    }

    private void doShare() {
        if (outputText.isEmpty()) {
            toast(getString(R.string.nothing_to_copy));
            return;
        }
        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType("text/plain");
        send.putExtra(Intent.EXTRA_TEXT, outputText);
        startActivity(Intent.createChooser(send, getString(R.string.btn_share)));
    }

    private void doClear() {
        setOutput("");
        cardResult.setVisibility(View.GONE);
        status.setVisibility(View.GONE);
    }

    // -----------------------------------------------------------------------
    // Presentation
    // -----------------------------------------------------------------------

    private String describe(Stego.Report r) {
        StringBuilder sb = new StringBuilder(r.describe());
        if (r.containerSize > 0) {
            sb.append("\n").append(r.containerSize).append(" bytes → ")
                    .append(r.carriers).append(" invisible characters");
        }
        return sb.toString();
    }

    /** Turns a failure into something the user can act on. */
    private String explain(StegoException e, String text) {
        switch (e.kind) {
            case BAD_MAGIC:
                if (Stego.isLegacyEncrypted(text)) {
                    return "This is an old v2 encrypted payload. v2 derived its key from a bare "
                            + "SHA-256, so this version refuses it by design. Open it with the old "
                            + "tool and hide it again here.";
                }
                return e.getMessage();
            case TRUNCATED:
                return e.getMessage()
                        + "\nMany apps strip invisible characters. Try sending it as a file instead.";
            default:
                return e.getMessage();
        }
    }

    private void setOutput(String text) {
        outputText = text;
        output.setText(text.isEmpty() ? getString(R.string.result_placeholder) : text);
        cardResult.setVisibility(text.isEmpty() ? View.GONE : View.VISIBLE);
    }

    private void showStatus(String message) {
        status.setText(message);
        status.setVisibility(View.VISIBLE);
    }

    private void busy(int messageRes) {
        progress.setVisibility(View.VISIBLE);
        showStatus(getString(messageRes));
        setEnabled(false);
    }

    private void idle() {
        progress.setVisibility(View.GONE);
        setEnabled(true);
    }

    private void setEnabled(boolean enabled) {
        findViewById(R.id.btn_hide).setEnabled(enabled);
        findViewById(R.id.btn_reveal).setEnabled(enabled);
    }

    private void toast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }
}
