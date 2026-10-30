//! parsers/pdf.rs — Deep PDF metadata parser using lopdf.

use crate::errors::NexGenError;
use crate::models::{FileMetadata, PdfSignatureStatus};

pub fn parse_pdf(data: &[u8], metadata: &mut FileMetadata) -> Result<(), NexGenError> {
    let doc = match lopdf::Document::load_mem(data) {
        Ok(d) => d,
        Err(e) => {
            if let Some(errs) = metadata.parse_errors.as_mut() {
                errs.push(format!("PDF parse error: {}", e));
            } else {
                metadata.parse_errors = Some(vec![format!("PDF parse error: {}", e)]);
            }
            return Ok(());
        }
    };

    metadata.pdf_version = Some(doc.version.clone());
    metadata.pdf_page_count = Some(doc.get_pages().len() as u32);
    let is_enc = doc.trailer.has(b"Encrypt");
    metadata.pdf_is_encrypted = Some(is_enc);
    metadata.pdf_encrypted = Some(if is_enc { "Yes".to_string() } else { "No".to_string() });

    // Extract Info dictionary metadata
    if let Ok(info_dict) = doc.trailer.get(b"Info") {
        if let Ok(dict) = doc.get_dictionary(info_dict.as_reference().unwrap_or((0, 0))) {
            if let Ok(author) = dict.get(b"Author") {
                metadata.pdf_author = author.as_str().ok().map(|s| String::from_utf8_lossy(s).to_string());
            }
            if let Ok(title) = dict.get(b"Title") {
                metadata.pdf_title = title.as_str().ok().map(|s| String::from_utf8_lossy(s).to_string());
            }
            if let Ok(subject) = dict.get(b"Subject") {
                metadata.pdf_subject = subject.as_str().ok().map(|s| String::from_utf8_lossy(s).to_string());
            }
            if let Ok(creator) = dict.get(b"Creator") {
                let c = creator.as_str().ok().map(|s| String::from_utf8_lossy(s).to_string());
                metadata.pdf_creator_app = c.clone();
                metadata.pdf_creator = c;
            }
            if let Ok(producer) = dict.get(b"Producer") {
                let p = producer.as_str().ok().map(|s| String::from_utf8_lossy(s).to_string());
                metadata.pdf_producer = p.clone();
            }
            if let Ok(creation_date) = dict.get(b"CreationDate") {
                metadata.pdf_creation_date = creation_date.as_str().ok().map(|s| String::from_utf8_lossy(s).to_string());
            }
            if let Ok(mod_date) = dict.get(b"ModDate") {
                metadata.pdf_modification_date = mod_date.as_str().ok().map(|s| String::from_utf8_lossy(s).to_string());
            }
            if let Ok(keywords) = dict.get(b"Keywords") {
                metadata.pdf_keywords = keywords.as_str().ok().map(|s| String::from_utf8_lossy(s).to_string());
            }
        }
    }

    // Check for Linearized PDF (in first 1024 bytes or root objects)
    let is_linearized = data.windows(11).any(|w| w == b"/Linearized");
    metadata.pdf_linearized = Some(if is_linearized { "Yes".to_string() } else { "No".to_string() });

    // Inspect Catalog (Root) for forms, signatures, mark info (tagged), and embedded files
    let mut has_forms = false;
    let mut has_embedded = false;
    let mut has_signatures = false;
    let mut is_tagged = false;

    if let Ok(root_obj) = doc.trailer.get(b"Root") {
        if let Ok(catalog) = doc.get_dictionary(root_obj.as_reference().unwrap_or((0, 0))) {
            has_forms = catalog.has(b"AcroForm");
            is_tagged = catalog.has(b"MarkInfo");

            // Embedded files (/Names -> /EmbeddedFiles)
            if let Ok(names_obj) = catalog.get(b"Names") {
                if let Ok(names_dict) = doc.get_dictionary(names_obj.as_reference().unwrap_or((0, 0))) {
                    has_embedded = names_dict.has(b"EmbeddedFiles");
                }
            }

            // Signatures check in AcroForm
            if has_forms {
                if let Ok(acro) = catalog.get(b"AcroForm") {
                    if let Ok(acro_dict) = doc.get_dictionary(acro.as_reference().unwrap_or((0, 0))) {
                        if acro_dict.has(b"SigFlags") || acro_dict.has(b"Fields") {
                            has_signatures = true;
                            metadata.pdf_signature_status = Some(PdfSignatureStatus::Valid);
                        }
                    }
                }
            }
        }
    }

    metadata.pdf_has_forms = Some(has_forms);
    metadata.pdf_has_embedded_files = Some(has_embedded);
    metadata.pdf_tagged = Some(if is_tagged { "Yes".to_string() } else { "No".to_string() });
    metadata.pdf_has_signatures = Some(if has_signatures { "Yes".to_string() } else { "No".to_string() });

    if metadata.pdf_signature_status.is_none() {
        metadata.pdf_signature_status = Some(if has_signatures { PdfSignatureStatus::Valid } else { PdfSignatureStatus::Unsigned });
    }

    // Check for annotations & compute page size from first page
    let mut has_annots = false;
    let pages = doc.get_pages();
    for (_page_num, page_id) in pages.iter() {
        if let Ok(page_dict) = doc.get_dictionary(*page_id) {
            if page_dict.has(b"Annots") {
                has_annots = true;
            }
            if metadata.pdf_page_size.is_none() {
                if let Ok(mbox) = page_dict.get(b"MediaBox") {
                    if let Ok(arr) = mbox.as_array() {
                        if arr.len() >= 4 {
                            let w_pt = (arr[2].as_float().unwrap_or(0.0) - arr[0].as_float().unwrap_or(0.0)).abs();
                            let h_pt = (arr[3].as_float().unwrap_or(0.0) - arr[1].as_float().unwrap_or(0.0)).abs();
                            let w_in = w_pt / 72.0;
                            let h_in = h_pt / 72.0;
                            metadata.pdf_page_size = Some(format!("{:.1} x {:.1} in ({:.0} x {:.0} pt)", w_in, h_in, w_pt, h_pt));
                        }
                    }
                }
            }
        }
    }
    metadata.pdf_has_annotations = Some(has_annots);

    Ok(())
}
