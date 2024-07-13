package com.suman.blogging.helper;

import com.cloudinary.Cloudinary;
import com.suman.blogging.exception.NotFoundException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import java.io.*;
import java.util.HashMap;
import java.util.Map;


@Service
@RequiredArgsConstructor
public class FileCRUD {

    private final Cloudinary cloudinary;
    private final ThreadPoolTaskExecutor taskExecutor;

    @Async
    public void uploadImage(@NonNull MultipartFile file,@NonNull String imageName,@NonNull String path) {
        File tempFile = copyToLocalDirectory(file);
        taskExecutor.execute(() -> {
            try {

                Map<String, Object> uploadParams = new HashMap<>();
                uploadParams.put("folder", path);
                uploadParams.put("public_id", imageName);
                uploadParams.put("quality", "auto");
                uploadParams.put("fetch_format", "auto");
                cloudinary.uploader().upload(tempFile, uploadParams);
            } catch (IOException e) {
                System.err.printf("IOException occurred while uploading image: {}" + e.getMessage(), e);
                throw new NotFoundException("Cannot upload image. Please try again" + e.getMessage());
            } finally {
                // Clean up the temporary file
                if (tempFile.exists()) {
                    tempFile.delete();
                }
            }
        });
    }

    public String updateUserImage(MultipartFile newImageFile, String oldImagePublicId, String newImageName, String path) {
        try {
            if (oldImagePublicId != null && !oldImagePublicId.isEmpty()) {
                Map<String, String> deleteParams = new HashMap<>();
                deleteParams.put("invalidate", "true");
                Map<?,?> destroyResult  = cloudinary.uploader().destroy(path + "/" + oldImagePublicId, deleteParams);
                System.out.println(destroyResult.toString());
                if (!"ok".equals(destroyResult.get("result"))) {
                    throw new NotFoundException("Failed to delete old image");
                }
                uploadImage(newImageFile,newImageName,path);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return newImageName;
    }
        public String getImageUrl(String imagePath, String folderPath) {
        String publicId = imagePath.startsWith(folderPath) ? imagePath.substring("UserImage/".length()) : imagePath;

        return cloudinary.url()
                .secure(true)
                .cloudName("dhmdgbhby")  // Replace with your actual cloud name
                .publicId("UserImage/" + publicId)
                .generate();
    }


    private File copyToLocalDirectory(MultipartFile file) {
        try {
            File tempFile = File.createTempFile("upload_", "_" + file.getOriginalFilename());
            try (InputStream inputStream = file.getInputStream();
                 OutputStream outputStream = new FileOutputStream(tempFile)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
            }
            return tempFile;
        } catch (IOException e) {
            System.out.println("IOException occurred while copying file to local directory: {}" + e.getMessage() + e);
            throw new NotFoundException("Cannot copy file to local directory. Please try again. " + e.getMessage());
        }
    }
}


