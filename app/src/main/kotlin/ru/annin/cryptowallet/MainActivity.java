package ru.annin.cryptowallet;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

import ru.annin.crypto.CryptoManager;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        new CryptoManager().stringFromJNI();
    }
}
