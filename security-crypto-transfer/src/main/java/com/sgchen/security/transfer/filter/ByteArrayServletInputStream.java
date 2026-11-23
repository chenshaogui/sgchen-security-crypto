package com.sgchen.security.transfer.filter;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import java.io.ByteArrayInputStream;

/**
 * 流复制
 *
 * @author sgchen
 * @date 2025/6/4 9:05
 */
public class ByteArrayServletInputStream extends ServletInputStream {

    private final ByteArrayInputStream buffer;

    public ByteArrayServletInputStream(byte[] contents) {
        this.buffer = new ByteArrayInputStream(contents);
    }

    @Override
    public int read() {
        return buffer.read();
    }

    @Override
    public boolean isFinished() {
        return buffer.available() == 0;
    }

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public void setReadListener(ReadListener readListener) {
        throw new UnsupportedOperationException();
    }
}
