use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use crate::error::Result;

const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
const LARGE_FILE_THRESHOLD: u64 = 100 * 1024 * 1024; // 100MB

pub struct StreamingReader {
    reader: BufReader<File>,
    file_size: u64,
    bytes_read: u64,
}

pub struct StreamingWriter {
    writer: BufWriter<File>,
    bytes_written: u64,
}

impl StreamingReader {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let file_size = file.metadata()?.len();
        let reader = BufReader::with_capacity(CHUNK_SIZE, file);
        
        Ok(StreamingReader {
            reader,
            file_size,
            bytes_read: 0,
        })
    }
    
    pub fn read_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let bytes_read = self.reader.read(&mut buffer)?;
        
        if bytes_read == 0 {
            return Ok(None);
        }
        
        self.bytes_read += bytes_read as u64;
        buffer.truncate(bytes_read);
        Ok(Some(buffer))
    }
    
    pub fn progress(&self) -> f64 {
        if self.file_size == 0 {
            0.0
        } else {
            (self.bytes_read as f64 / self.file_size as f64) * 100.0
        }
    }
    
    pub fn file_size(&self) -> u64 {
        self.file_size
    }
    
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
}

impl StreamingWriter {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::create(path)?;
        let writer = BufWriter::with_capacity(CHUNK_SIZE, file);
        
        Ok(StreamingWriter {
            writer,
            bytes_written: 0,
        })
    }
    
    pub fn new_optimized<P: AsRef<Path>>(path: P, file_size: u64) -> Result<Self> {
        let file = File::create(path)?;
        // Use larger buffer for large files
        let buffer_size = if file_size > LARGE_FILE_THRESHOLD {
            CHUNK_SIZE * 4 // 256KB for large files
        } else {
            CHUNK_SIZE
        };
        let writer = BufWriter::with_capacity(buffer_size, file);
        
        Ok(StreamingWriter {
            writer,
            bytes_written: 0,
        })
    }
    
    pub fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_all(data)?;
        self.bytes_written += data.len() as u64;
        Ok(())
    }
    
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
    
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

pub fn copy_file_streaming<P: AsRef<Path>, Q: AsRef<Path>>(
    src: P, 
    dst: Q
) -> Result<u64> {
    let mut reader = StreamingReader::new(src)?;
    let mut writer = StreamingWriter::new(dst)?;
    let mut total_bytes = 0u64;
    
    while let Some(chunk) = reader.read_chunk()? {
        writer.write_chunk(&chunk)?;
        total_bytes += chunk.len() as u64;
    }
    
    writer.flush()?;
    Ok(total_bytes)
}

pub fn process_file_in_chunks<F>(
    input_path: &str,
    output_path: &str,
    mut processor: F,
) -> Result<u64>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>>,
{
    let mut reader = StreamingReader::new(input_path)?;
    let mut writer = StreamingWriter::new(output_path)?;
    let mut total_bytes = 0u64;
    
    while let Some(chunk) = reader.read_chunk()? {
        let processed_chunk = processor(&chunk)?;
        writer.write_chunk(&processed_chunk)?;
        total_bytes += chunk.len() as u64;
    }
    
    writer.flush()?;
    Ok(total_bytes)
}

pub fn get_file_size<P: AsRef<Path>>(path: P) -> Result<u64> {
    let file = File::open(path)?;
    Ok(file.metadata()?.len())
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: u64 = 1024;
    
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD as f64;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

pub fn print_progress(current: u64, total: u64, operation: &str) {
    if total == 0 {
        return;
    }
    
    let percentage = (current as f64 / total as f64) * 100.0;
    let current_str = format_bytes(current);
    let total_str = format_bytes(total);
    
    print!("\r{}: {:.1}% ({}/{})", operation, percentage, current_str, total_str);
    std::io::stdout().flush().ok();
    
    if current >= total {
        println!();
    }
}
