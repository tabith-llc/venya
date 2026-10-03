// Copyright (c) 2026 Tabith LLC.
// Use of this source code is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository. As of the
// Change Date listed there, the work is available under MPL 2.0.
// SPDX-License-Identifier: BUSL-1.1

use pyo3::prelude::*;
use pyo3::types::{PyList, PyBytes, PyDict};

mod hashes;
mod filter;

/// compute_detection_hashes(secret_value: bytes) -> list[str]
#[pyfunction]
fn compute_detection_hashes(secret: &[u8]) -> PyResult<Vec<String>> {
    Ok(hashes::compute_detection_hashes(secret))
}

/// Parse a Python dict into a SecretEntry
fn parse_entry(dict: &Bound<'_, PyDict>) -> PyResult<filter::SecretEntry> {
    let secret_id: String = dict.get_item("secret_id")?.ok_or(pyo3::exceptions::PyKeyError::new_err("missing secret_id"))?.extract()?;
    let secret_value: Vec<u8> = dict.get_item("secret_value")?.ok_or(pyo3::exceptions::PyKeyError::new_err("missing secret_value"))?.extract()?;
    let id_len = secret_id.as_bytes().len();
    if id_len > 64 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "secret_id must be at most 64 bytes, got {id_len}"
        )));
    }
    Ok(filter::SecretEntry {
        secret_id,
        secret_value,
    })
}

fn parse_entries(entries: &Bound<'_, PyList>) -> PyResult<Vec<filter::SecretEntry>> {
    let mut secret_entries = Vec::new();
    for item in entries.iter() {
        let dict = item.downcast::<PyDict>()?;
        secret_entries.push(parse_entry(dict)?);
    }
    Ok(secret_entries)
}

/// filter_output(output: bytes, entries: list[dict]) -> tuple[bytes, list[str]]
#[pyfunction]
#[pyo3(signature = (output, entries))]
fn filter_output(
    py: Python<'_>,
    output: &[u8],
    entries: &Bound<'_, PyList>,
) -> PyResult<(PyObject, Vec<String>)> {
    let state = filter::FilterState::new(&parse_entries(entries)?);
    let (result, ids) = filter::filter_output(output, &state);

    Ok((PyBytes::new(py, &result).into(), ids))
}

/// filter_outputs(stdout: bytes, stderr: bytes, entries: list[dict])
/// -> tuple[bytes, bytes, list[str], list[str]]
/// Builds the filter state once and applies it to both streams.
#[pyfunction]
#[pyo3(signature = (stdout, stderr, entries))]
fn filter_outputs(
    py: Python<'_>,
    stdout: &[u8],
    stderr: &[u8],
    entries: &Bound<'_, PyList>,
) -> PyResult<(PyObject, PyObject, Vec<String>, Vec<String>)> {
    let state = filter::FilterState::new(&parse_entries(entries)?);
    let (masked_stdout, stdout_ids) = filter::filter_output(stdout, &state);
    let (masked_stderr, stderr_ids) = filter::filter_output(stderr, &state);

    Ok((
        PyBytes::new(py, &masked_stdout).into(),
        PyBytes::new(py, &masked_stderr).into(),
        stdout_ids,
        stderr_ids,
    ))
}

/// Rust-powered venya filter module
#[pymodule]
fn venya_filter(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(compute_detection_hashes, m)?)?;
    m.add_function(wrap_pyfunction!(filter_output, m)?)?;
    m.add_function(wrap_pyfunction!(filter_outputs, m)?)?;
    Ok(())
}
