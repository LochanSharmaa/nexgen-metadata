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
    metadata.pdf_is_encrypted = Some(doc.trailer.has(b"Encrypt"));

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
                metadata.pdf_creator_app = creator.as_str().ok().map(|s| String::from_utf8_lossy(s).to_string());
            }
            if let Ok(producer) = dict.get(b"Producer") {
                metadata.pdf_producer = producer.as_str().ok().map(|s| String::from_utf8_lossy(s).to_string());
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

    // Inspect Catalog (Root) for forms, signatures, and embedded files
    if let Ok(root_obj) = doc.trailer.get(b"Root") {
        if let Ok(catalog) = doc.get_dictionary(root_obj.as_reference().unwrap_or((0, 0))) {
            // AcroForm
            metadata.pdf_has_forms = Some(catalog.has(b"AcroForm"));

            // Embedded files (/Names -> /EmbeddedFiles)
            if let Ok(names_obj) = catalog.get(b"Names") {
                if let Ok(names_dict) = doc.get_dictionary(names_obj.as_reference().unwrap_or((0, 0))) {
                    metadata.pdf_has_embedded_files = Some(names_dict.has(b"EmbeddedFiles"));
                }
            } else {
                metadata.pdf_has_embedded_files = Some(false);
            }

            // Signatures
            if catalog.has(b"AcroForm") {
                if let Ok(acro) = catalog.get(b"AcroForm") {
                    if let Ok(acro_dict) = doc.get_dictionary(acro.as_reference().unwrap_or((0, 0))) {
                        if acro_dict.has(b"SigFlags") {
                            metadata.pdf_signature_status = Some(PdfSignatureStatus::Valid);
                        }
                    }
                }
            }
            if metadata.pdf_signature_status.is_none() {
                metadata.pdf_signature_status = Some(PdfSignatureStatus::Unsigned);
            }
        }
    }

    // Check for annotations across pages
    let mut has_annots = false;
    for (_page_num, page_id) in doc.get_pages() {
        if let Ok(page_dict) = doc.get_dictionary(page_id) {
            if page_dict.has(b"Annots") {
                has_annots = true;
                break;
            }
        }
    }
    metadata.pdf_has_annotations = Some(has_annots);

    Ok(())
}
