use std::collections::BTreeMap;

use object::{LittleEndian as LE, Object, pe, read::Bytes, read::pe::PeFile64};

use crate::image::{Address, Budget, Error, Import};

#[derive(Default)]
pub(crate) struct PeAnalysis {
    pub ranges: Vec<(Address, Address)>,
    pub imports: BTreeMap<Address, Import>,
}

pub(crate) fn read(bytes: &[u8], budget: &mut Budget) -> Result<PeAnalysis, Error> {
    let file = PeFile64::parse(bytes).map_err(Error::malformed)?;
    let image_base = file.relative_address_base();
    let mut result = PeAnalysis::default();
    let address = |rva: u64| {
        image_base
            .checked_add(rva)
            .map(Address)
            .ok_or_else(|| Error::malformed("PE analysis address overflow"))
    };

    if let Some(directory) = file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        let data = directory
            .data(bytes, &file.section_table())
            .map_err(Error::malformed)?;
        if data.len() % 12 != 0 {
            return Err(Error::malformed("misaligned PE runtime function table"));
        }
        let records = Bytes(data)
            .read_slice::<pe::ImageRuntimeFunctionEntry>(data.len() / 12)
            .map_err(|()| Error::malformed("invalid PE runtime function table"))?;
        for record in records {
            budget.record()?;
            let begin = record.begin_address.get(LE);
            let end = record.end_address.get(LE);
            if begin != 0 && begin < end {
                result
                    .ranges
                    .push((address(begin.into())?, address(end.into())?));
            }
        }
    }

    if let Some(table) = file.import_table().map_err(Error::malformed)? {
        let mut descriptors = table.descriptors().map_err(Error::malformed)?;
        while let Some(descriptor) = descriptors.next().map_err(Error::malformed)? {
            budget.record()?;
            let first_slot = descriptor.first_thunk.get(LE);
            if first_slot == 0 {
                continue;
            }
            let library = table
                .name(descriptor.name.get(LE))
                .map_err(Error::malformed)?;
            let original = descriptor.original_first_thunk.get(LE);
            let mut thunks = table
                .thunks(if original == 0 { first_slot } else { original })
                .map_err(Error::malformed)?;
            let mut slot = first_slot;
            while let Some(thunk) = thunks
                .next::<pe::ImageNtHeaders64>()
                .map_err(Error::malformed)?
            {
                budget.record()?;
                let name = match table
                    .import::<pe::ImageNtHeaders64>(thunk)
                    .map_err(Error::malformed)?
                {
                    object::read::pe::Import::Name(_, name) => budget.name(name)?,
                    object::read::pe::Import::Ordinal(ordinal) => format!("#{ordinal}"),
                };
                let import = Import {
                    library: budget.name(library)?,
                    name,
                };
                let location = address(slot.into())?;
                if let Some(previous) = result.imports.get(&location)
                    && previous != &import
                {
                    return Err(Error::malformed("multiple imports claim the same PE slot"));
                }
                result.imports.insert(location, import);
                slot = slot
                    .checked_add(8)
                    .ok_or_else(|| Error::malformed("PE import slot RVA overflow"))?;
            }
        }
    }
    Ok(result)
}
