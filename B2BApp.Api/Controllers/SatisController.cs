﻿using B2BApp.Business.Abstract;
using B2BApp.DTOs;
using B2BApp.Entities.Concrete;
using Core.Models.Concrete;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;

namespace B2BApp.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SatisController : ControllerBase
    {
        private readonly ISatisService _satisService;

        public SatisController(ISatisService satisService)
        {
            _satisService = satisService;
        }


        [HttpPost]
        public Result<Satis> PostCompany(Satis satis)
        {

            _satisService.addSatis(satis);
            return new Result<Satis>
            {
                Data = satis,
                Message = "Satis başarıyla eklendi",
                StatusCode = StatusCodes.Status200OK
            };
        }
        [HttpGet]
        public Result<Satis> GetCompany(string id)
        {

            var satis = _satisService.getSatisById(ObjectId.Parse(id));
            return satis;
        }
        [HttpGet("all")]
        public Result<ICollection<Satis>> GetCompany()
        {
            var satislar = _satisService.getAll();
            return satislar;
        }



        [HttpPut]
        public Result<Satis> UpdateCompany(SatisDto satisDto,  string satisId)
        {
            Satis satis = new Satis 
            {
                Id = ObjectId.Parse(satisDto.ObjectId.ToString()) ,
                SubeId = ObjectId.Parse(satisDto.SubeId.ToString()),
                UrunId = ObjectId.Parse(satisDto.UrunId.ToString()),
                SatisMiktari = satisDto.SatisMiktari,
                SatisTarihi = satisDto.SatisTarihi,
                Toplam = satisDto.Toplam,
                
            };



            _satisService.updateSatis(satis, satisId);
            return new Result<Satis>
            {
                Data = satis,
                Message = "Satis başarıyla güncellendi",
                StatusCode = StatusCodes.Status200OK
            };
        }

        [HttpDelete]
        public Result<Satis> DeleteCompany(string id)
        {
            _satisService.deleteSatis(ObjectId.Parse(id));

            return new Result<Satis>
            {
                Message = "Satis başarıyla silindi",
                StatusCode = StatusCodes.Status200OK
            };
        }
    }
}