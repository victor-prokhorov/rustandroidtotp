package com.victorprokhorov.rustandroidtotp;

import android.widget.TextView;

public class Bindings {
    static {
        System.loadLibrary("rustandroidtotp");
    }

    private TextView textView;

    public Bindings(TextView textView) {
        this.textView = textView;
    }

    public static native void main(final byte[] database, final byte[] password, Bindings callback);

    public void callback(String message) {
        textView.post(() -> 
            textView.setText(message)
        );
    }
}



