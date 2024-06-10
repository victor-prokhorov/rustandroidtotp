package com.victorprokhorov.rustandroidtotp;

import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class MainActivity extends AppCompatActivity {
    private TextView textView;
    private ActivityResultLauncher<Intent> filePickerLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        textView = new TextView(this);
        setContentView(textView);

        filePickerLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                        Uri fileUri = result.getData().getData();
                        textView.setText("Picked file URI: " + fileUri.toString());
                        promptForPasswordAndDecrypt(fileUri);
                    } else {
                        textView.setText("File picking canceled or failed.");
                    }
                }
        );

        openFilePicker();
    }

    private void openFilePicker() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        filePickerLauncher.launch(intent);
    }

    private void promptForPasswordAndDecrypt(Uri fileUri) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Enter Password");

        final EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);

        final CheckBox showPassword = new CheckBox(this);
        showPassword.setText("Show Password");
        showPassword.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (isChecked) {
                input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
            } else {
                input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            }
        });

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.addView(input);
        layout.addView(showPassword);
        builder.setView(layout);

        builder.setPositiveButton("OK", (dialog, which) -> {
            String password = input.getText().toString();
            try {
                byte[] fileBytes = readBytesFromFileUri(fileUri);
                Bindings.main(fileBytes, password.getBytes(), new Bindings(textView));
            } catch (IOException e) {
                textView.setText("IOException: " + e.getMessage());
            }
        });
        builder.setNegativeButton("Cancel", (dialog, which) -> {
            dialog.cancel();
            textView.setText("Password entry canceled.");
        });

        builder.show();
    }

    private byte[] readBytesFromFileUri(Uri uri) throws IOException {
        try (InputStream inputStream = getContentResolver().openInputStream(uri);
            ByteArrayOutputStream byteBuffer = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int len;
            while (true) {
                assert inputStream != null;
                if ((len = inputStream.read(buffer)) == -1) break;
                byteBuffer.write(buffer, 0, len);
            }
            return byteBuffer.toByteArray();
        }
    }
}
