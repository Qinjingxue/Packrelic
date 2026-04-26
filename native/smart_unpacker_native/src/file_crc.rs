use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const BUFFER_SIZE: usize = 1024 * 1024;

#[pyfunction]
pub(crate) fn compute_directory_crc_manifest(
    py: Python<'_>,
    output_dir: &str,
    max_files: Option<usize>,
) -> PyResult<Py<PyDict>> {
    let root = PathBuf::from(output_dir);
    let result = PyDict::new(py);
    let files = PyList::empty(py);
    let errors = PyList::empty(py);
    result.set_item("files", &files)?;
    result.set_item("errors", &errors)?;

    if !root.exists() {
        result.set_item("status", "missing")?;
        return Ok(result.unbind());
    }
    if !root.is_dir() {
        result.set_item("status", "not_directory")?;
        return Ok(result.unbind());
    }

    let limit = max_files.unwrap_or(usize::MAX);
    let mut total_files = 0usize;
    let mut scanned_files = 0usize;
    walk_directory(py, &root, &root, limit, &mut total_files, &mut scanned_files, &files, &errors)?;
    result.set_item("status", "ok")?;
    result.set_item("total_files", total_files)?;
    result.set_item("scanned_files", scanned_files)?;
    result.set_item("truncated", scanned_files < total_files)?;
    Ok(result.unbind())
}

#[pyfunction]
pub(crate) fn sample_directory_readability(
    py: Python<'_>,
    output_dir: &str,
    max_samples: Option<usize>,
    read_bytes: Option<usize>,
) -> PyResult<Py<PyDict>> {
    let root = PathBuf::from(output_dir);
    let result = PyDict::new(py);
    let samples = PyList::empty(py);
    let errors = PyList::empty(py);
    result.set_item("samples", &samples)?;
    result.set_item("errors", &errors)?;

    if !root.exists() {
        result.set_item("status", "missing")?;
        return Ok(result.unbind());
    }
    if !root.is_dir() {
        result.set_item("status", "not_directory")?;
        return Ok(result.unbind());
    }

    let max_samples = max_samples.unwrap_or(64).max(1);
    let read_bytes = read_bytes.unwrap_or(4096).max(1);
    let mut file_paths = Vec::new();
    collect_regular_files(&root, &root, &mut file_paths, &errors, py)?;

    let selected = select_sample_paths(&file_paths, max_samples);
    let mut readable_files = 0usize;
    let mut empty_files = 0usize;
    let mut unreadable_files = 0usize;
    let mut bytes_read = 0u64;

    for path in selected {
        match read_sample(&path, read_bytes) {
            Ok(sample) => {
                readable_files += 1;
                if sample.size == 0 {
                    empty_files += 1;
                }
                bytes_read += sample.bytes_read;
                let item = PyDict::new(py);
                item.set_item("path", relative_path(&path, &root))?;
                item.set_item("size", sample.size)?;
                item.set_item("bytes_read", sample.bytes_read)?;
                item.set_item("empty", sample.size == 0)?;
                samples.append(item)?;
            }
            Err(err) => {
                unreadable_files += 1;
                append_error(py, &errors, &path, &root, &err.to_string())?;
            }
        }
    }

    result.set_item("status", "ok")?;
    result.set_item("total_files", file_paths.len())?;
    result.set_item("sampled_files", readable_files + unreadable_files)?;
    result.set_item("readable_files", readable_files)?;
    result.set_item("unreadable_files", unreadable_files)?;
    result.set_item("empty_files", empty_files)?;
    result.set_item("bytes_read", bytes_read)?;
    result.set_item("truncated", file_paths.len() > max_samples)?;
    Ok(result.unbind())
}

fn walk_directory(
    py: Python<'_>,
    root: &Path,
    current: &Path,
    limit: usize,
    total_files: &mut usize,
    scanned_files: &mut usize,
    files: &Bound<'_, PyList>,
    errors: &Bound<'_, PyList>,
) -> PyResult<()> {
    let entries = match std::fs::read_dir(current) {
        Ok(entries) => entries,
        Err(err) => {
            append_error(py, errors, current, root, &err.to_string())?;
            return Ok(());
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                append_error(py, errors, current, root, &err.to_string())?;
                continue;
            }
        };
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(err) => {
                append_error(py, errors, &path, root, &err.to_string())?;
                continue;
            }
        };
        if metadata.is_dir() {
            walk_directory(py, root, &path, limit, total_files, scanned_files, files, errors)?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        *total_files += 1;
        if *scanned_files >= limit {
            continue;
        }
        match crc32_file(&path) {
            Ok(crc32) => {
                let item = PyDict::new(py);
                item.set_item("path", relative_path(&path, root))?;
                item.set_item("size", metadata.len())?;
                item.set_item("crc32", crc32)?;
                files.append(item)?;
                *scanned_files += 1;
            }
            Err(err) => append_error(py, errors, &path, root, &err.to_string())?,
        }
    }
    Ok(())
}

fn append_error(
    py: Python<'_>,
    errors: &Bound<'_, PyList>,
    path: &Path,
    root: &Path,
    message: &str,
) -> PyResult<()> {
    let item = PyDict::new(py);
    item.set_item("path", relative_path(path, root))?;
    item.set_item("message", message)?;
    errors.append(item)
}

fn collect_regular_files(
    root: &Path,
    current: &Path,
    paths: &mut Vec<PathBuf>,
    errors: &Bound<'_, PyList>,
    py: Python<'_>,
) -> PyResult<()> {
    let entries = match std::fs::read_dir(current) {
        Ok(entries) => entries,
        Err(err) => {
            append_error(py, errors, current, root, &err.to_string())?;
            return Ok(());
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                append_error(py, errors, current, root, &err.to_string())?;
                continue;
            }
        };
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(err) => {
                append_error(py, errors, &path, root, &err.to_string())?;
                continue;
            }
        };
        if metadata.is_dir() {
            collect_regular_files(root, &path, paths, errors, py)?;
        } else if metadata.is_file() {
            paths.push(path);
        }
    }
    Ok(())
}

fn select_sample_paths(paths: &[PathBuf], max_samples: usize) -> Vec<PathBuf> {
    if paths.len() <= max_samples {
        return paths.to_vec();
    }
    if max_samples == 1 {
        return vec![paths[0].clone()];
    }
    let last = paths.len() - 1;
    (0..max_samples)
        .map(|index| {
            let selected = index * last / (max_samples - 1);
            paths[selected].clone()
        })
        .collect()
}

struct ReadSample {
    size: u64,
    bytes_read: u64,
}

fn read_sample(path: &Path, read_bytes: usize) -> std::io::Result<ReadSample> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(ReadSample { size, bytes_read: 0 });
    }
    let mut buffer = vec![0u8; read_bytes];
    let head_read = file.read(&mut buffer)? as u64;
    let mut tail_read = 0u64;
    if size > read_bytes as u64 {
        let tail_offset = size.saturating_sub(read_bytes as u64);
        file.seek(SeekFrom::Start(tail_offset))?;
        tail_read = file.read(&mut buffer)? as u64;
    }
    Ok(ReadSample {
        size,
        bytes_read: head_read + tail_read,
    })
}

fn relative_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn crc32_file(path: &Path) -> std::io::Result<u32> {
    let mut file = File::open(path)?;
    let mut crc = 0xFFFF_FFFFu32;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        crc = crc32_update(crc, &buffer[..read]);
    }
    Ok(!crc)
}

fn crc32_update(mut crc: u32, bytes: &[u8]) -> u32 {
    let table = crc32_table();
    for byte in bytes {
        let index = ((crc ^ u32::from(*byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[index];
    }
    crc
}

fn crc32_table() -> &'static [u32; 256] {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        for i in 0..256u32 {
            let mut crc = i;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
            table[i as usize] = crc;
        }
        table
    })
}
