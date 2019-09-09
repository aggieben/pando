pub mod cor;

pub enum CorErr {

}

pub struct TypeDef {

}

pub struct TypeRef {

}

pub struct ModuleRef {

}

pub struct AssemblyRef {

}

pub enum TypeHandle {
    TypeDef(TypeDef),
    TypeRef(TypeRef)
}

pub enum ResolutionScope {
    Module(ModuleRef),
    Assembly(AssemblyRef),
    Type(TypeRef)
}

pub trait MetaDataImporter {
    // The following are from the IMetaDataImporter interface

    // CloseEnum
    // CountEnum
    // EnumCustomAttributes
    // EnumEvents
    // EnumFields
    // EnumFieldsWithName
    // EnumInterfaceImpls
    // EnumMemberRefs
    // EnumMembers
    // EnumMembersWithName
    // EnumMethodImpls
    // EnumMethods
    // EnumMethodsWithName
    // EnumModuleRefs
    // EnumParams
    // EnumPermissionSets
    // EnumProperties
    // EnumSignatures
    // EnumTypeDefs
    // EnumTypeRefs
    // EnumTypeSpecs
    // EnumUnresolvedMethods
    // EnumUserStrings
    // FindField
    // FindMember
    // FindMemberRef
    // FindMethod

    /// This function implements FindTypeDefByName from the IMetaDataImporter interface
    fn find_typedef(name: &str, enclosing_type: Option<&TypeHandle>) -> Result<TypeDef, CorErr>;

    /// This function implements FindTypeRef from the IMetaDataImporter interface
    fn find_typeref(scope: &ResolutionScope, name: &str) -> TypeRef;

    // GetClassLayout
    // GetCustomAttributeByName
    // GetCustomAttributeProps
    // GetEventProps
    // GetFieldMarshal
    // GetFieldProps
    // GetInterfaceImplProps
    // GetMemberProps
    // GetMemberRefProps
    // GetMethodProps
    // GetMethodSemantics
    // GetModuleFromScope
    // GetModuleRefProps
    // GetNameFromToken [obsolete]
    // GetNativeCallConvFromSig
    // GetNestedClassProps
    // GetParamForMethodIndex
    // GetParamProps
    // GetPrmissionSetProps
    // GetPinvokeMap
    // GetPropertyProps
    // GetRVA
    // GetScopeProps
    // GetSigFromToken
    // GetTypeDefProps
    // GetTypeRefProps
    // GetTypeSpecFromToken
    // GetUserString
    // IsGlobal
    // IsValidToken
    // ResetEnum
    // ResolveTypeRef

    // The following are from the IMetaDataImport2 interface
    // EnumGenericParamConstraints
    // EnumGenericParams
    // EnumMethodSpecs
    // GetGenericParamConstraintProps
    // GetGenericParamProps
    // GetMethodSpecProps
    // GetPEKind
    
    // GetVersionString
    fn get_version_string() -> Result<String, CorErr>;
}